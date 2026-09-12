#![forbid(unsafe_code)]
//! Cross-camera extrinsics solver interface and calibration certificate subsystem (FSS-090 / WP-110).
//!
//! Provides a deterministic, typed, immutable calibration certificate binding:
//! - Rigid 3D coordinate transform $SE(3)$ (3x3 rotation matrix and translation vector in mm)
//! - Calibration residual (mean error, max error, RMSE in micro-pixels, and 3D alignment RMSE)
//! - 6-DOF parameter covariance (rotation variances in $\mu\text{rad}^2$ and translation variances in $\mu\text{mm}^2$)
//! - Time validity interval ([`CaptureInterval`])
//! - Retained correspondence evidence from which the transform was fitted
//! - Physical device identities, hardware generations, firmware generations, and intrinsics certificates
//!
//! Enforces:
//! - Bit-identical determinism using fixed-point representation [`Fixed64`] with documented IEEE 754 platform stability
//! - Explicit rejection of default identity transforms
//! - Rejection of self-camera pairs (source and target must be distinct devices)
//! - Closed-form deterministic reference solver based on Horn's absolute orientation algorithm and Jacobi eigensolver
//! - Typed failure states for insufficient, degenerate, or high-residual correspondences
//! - Contradiction detection against active certificates triggering automatic invalidation
//! - Rigorous bounds tested at bound and bound+1

use std::collections::BTreeSet;
use std::fmt;

use fss_core::{
    CalibrationGeneration, CanonicalEncode, CanonicalEncoder, CaptureInterval, ContentDigest,
    ContractError, DeviceGeneration, DeviceId, FirmwareGeneration, TimestampNs,
};

use crate::calibration::{
    CalibrationError, CameraIntrinsics, Fixed64, IntrinsicsCertificate, MICRO_UNIT_SCALE,
};
use crate::error::ReferenceError;

/// Maximum number of cross-camera correspondence observations allowed in a single certificate.
pub const MAX_EXTRINSICS_CORRESPONDENCES: usize = 512;

/// Minimum number of cross-camera correspondence observations required for a non-degenerate 3D fit.
pub const MIN_EXTRINSICS_CORRESPONDENCES: usize = 8;

/// Maximum byte length for an extrinsics calibration certificate identifier.
pub const MAX_CERTIFICATE_ID_BYTES: usize = 128;

/// Maximum permissible root-mean-square reprojection error in micro-pixels (10.0 pixels = 10,000,000 upx).
pub const MAX_EXTRINSICS_REPROJECTION_TOLERANCE_UPX: u64 = 10_000_000;

/// Minimum 3D spatial spread required along each coordinate axis in millimeters.
pub const MIN_SPATIAL_SPREAD_MM: i32 = 10;

/// Rigid 3D coordinate frame transformation $SE(3)$ represented with micro-unit fixed-point precision.
///
/// Maps a 3D point $P_{\text{source}}$ in the source camera frame to $P_{\text{target}}$ in the target camera frame:
/// $$P_{\text{target}} = R \cdot P_{\text{source}} + T$$
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RigidTransform3D {
    /// 3x3 orthonormal rotation matrix $R$.
    pub rotation: [[Fixed64; 3]; 3],
    /// 3D translation vector $T$ in millimeters $[t_x, t_y, t_z]$.
    pub translation_mm: [Fixed64; 3],
}

impl RigidTransform3D {
    /// Identity transform (strictly prohibited as a default calibrated extrinsics certificate).
    pub const IDENTITY: Self = Self {
        rotation: [
            [Fixed64::ONE, Fixed64::ZERO, Fixed64::ZERO],
            [Fixed64::ZERO, Fixed64::ONE, Fixed64::ZERO],
            [Fixed64::ZERO, Fixed64::ZERO, Fixed64::ONE],
        ],
        translation_mm: [Fixed64::ZERO, Fixed64::ZERO, Fixed64::ZERO],
    };

    /// Constructs a rigid transform directly from fixed-point rotation matrix and translation vector.
    #[must_use]
    pub const fn from_parts(rotation: [[Fixed64; 3]; 3], translation_mm: [Fixed64; 3]) -> Self {
        Self {
            rotation,
            translation_mm,
        }
    }

    /// Constructs a rigid transform from IEEE 754 floating-point components using deterministic rounding.
    pub fn from_f64_parts(
        rotation: [[f64; 3]; 3],
        translation_mm: [f64; 3],
    ) -> Result<Self, ExtrinsicsError> {
        for row in &rotation {
            for &val in row {
                if !val.is_finite() {
                    return Err(ExtrinsicsError::InvalidTransform(
                        "rotation matrix contains non-finite float (NaN or Inf)".to_string(),
                    ));
                }
            }
        }
        for &val in &translation_mm {
            if !val.is_finite() {
                return Err(ExtrinsicsError::InvalidTransform(
                    "translation vector contains non-finite float (NaN or Inf)".to_string(),
                ));
            }
        }

        let r_fixed = [
            [
                Fixed64::from_f64(rotation[0][0])?,
                Fixed64::from_f64(rotation[0][1])?,
                Fixed64::from_f64(rotation[0][2])?,
            ],
            [
                Fixed64::from_f64(rotation[1][0])?,
                Fixed64::from_f64(rotation[1][1])?,
                Fixed64::from_f64(rotation[1][2])?,
            ],
            [
                Fixed64::from_f64(rotation[2][0])?,
                Fixed64::from_f64(rotation[2][1])?,
                Fixed64::from_f64(rotation[2][2])?,
            ],
        ];
        let t_fixed = [
            Fixed64::from_f64(translation_mm[0])?,
            Fixed64::from_f64(translation_mm[1])?,
            Fixed64::from_f64(translation_mm[2])?,
        ];
        let transform = Self {
            rotation: r_fixed,
            translation_mm: t_fixed,
        };
        transform.validate_orthogonality()?;
        if transform.is_identity() {
            return Err(ExtrinsicsError::InvalidTransform(
                "default identity extrinsics transform is strictly prohibited".to_string(),
            ));
        }
        Ok(transform)
    }

    /// Returns true if this transform is an uncalibrated identity transform ($R = I, T = \mathbf{0}$).
    #[must_use]
    pub fn is_identity(&self) -> bool {
        self.rotation == Self::IDENTITY.rotation
            && self.translation_mm == Self::IDENTITY.translation_mm
    }

    /// Validates that the rotation matrix is strictly orthonormal with $\det(R) \approx 1$.
    pub fn validate_orthogonality(&self) -> Result<(), ExtrinsicsError> {
        let r = [
            [
                self.rotation[0][0].to_f64(),
                self.rotation[0][1].to_f64(),
                self.rotation[0][2].to_f64(),
            ],
            [
                self.rotation[1][0].to_f64(),
                self.rotation[1][1].to_f64(),
                self.rotation[1][2].to_f64(),
            ],
            [
                self.rotation[2][0].to_f64(),
                self.rotation[2][1].to_f64(),
                self.rotation[2][2].to_f64(),
            ],
        ];

        // Check determinant: det(R) = r00*(r11*r22 - r12*r21) - r01*(r10*r22 - r12*r20) + r02*(r10*r21 - r11*r20)
        let det = r[0][0] * (r[1][1] * r[2][2] - r[1][2] * r[2][1])
            - r[0][1] * (r[1][0] * r[2][2] - r[1][2] * r[2][0])
            + r[0][2] * (r[1][0] * r[2][1] - r[1][1] * r[2][0]);

        if !det.is_finite() || (det - 1.0).abs() > 0.05 {
            let det_upx = if det.is_finite() {
                (det * (MICRO_UNIT_SCALE as f64)).round() as i64
            } else {
                0
            };
            return Err(ExtrinsicsError::NonOrthogonalRotation { det_upx });
        }

        // Check R * R^T \approx I
        for i in 0..3 {
            for j in 0..3 {
                let dot = r[i][0] * r[j][0] + r[i][1] * r[j][1] + r[i][2] * r[j][2];
                let expected = if i == j { 1.0 } else { 0.0 };
                if !dot.is_finite() || (dot - expected).abs() > 0.05 {
                    let det_upx = if det.is_finite() {
                        (det * (MICRO_UNIT_SCALE as f64)).round() as i64
                    } else {
                        0
                    };
                    return Err(ExtrinsicsError::NonOrthogonalRotation { det_upx });
                }
            }
        }

        Ok(())
    }

    /// Transforms a 3D point in millimeters using IEEE 754 floating-point arithmetic.
    #[must_use]
    pub fn transform_point_f64(&self, p: [f64; 3]) -> [f64; 3] {
        let [x, y, z] = p;
        let r = [
            [
                self.rotation[0][0].to_f64(),
                self.rotation[0][1].to_f64(),
                self.rotation[0][2].to_f64(),
            ],
            [
                self.rotation[1][0].to_f64(),
                self.rotation[1][1].to_f64(),
                self.rotation[1][2].to_f64(),
            ],
            [
                self.rotation[2][0].to_f64(),
                self.rotation[2][1].to_f64(),
                self.rotation[2][2].to_f64(),
            ],
        ];
        let t = [
            self.translation_mm[0].to_f64(),
            self.translation_mm[1].to_f64(),
            self.translation_mm[2].to_f64(),
        ];

        [
            r[0][0] * x + r[0][1] * y + r[0][2] * z + t[0],
            r[1][0] * x + r[1][1] * y + r[1][2] * z + t[1],
            r[2][0] * x + r[2][1] * y + r[2][2] * z + t[2],
        ]
    }

    /// Transforms a 3D point using exact integer fixed-point arithmetic.
    pub fn transform_point_fixed(&self, p: [Fixed64; 3]) -> Result<[Fixed64; 3], ExtrinsicsError> {
        let [x, y, z] = p;

        let r00_x = self.rotation[0][0]
            .checked_mul(x)
            .ok_or(ExtrinsicsError::ArithmeticOverflow)?;
        let r01_y = self.rotation[0][1]
            .checked_mul(y)
            .ok_or(ExtrinsicsError::ArithmeticOverflow)?;
        let r02_z = self.rotation[0][2]
            .checked_mul(z)
            .ok_or(ExtrinsicsError::ArithmeticOverflow)?;
        let tx = r00_x
            .checked_add(r01_y)
            .and_then(|val| val.checked_add(r02_z))
            .and_then(|val| val.checked_add(self.translation_mm[0]))
            .ok_or(ExtrinsicsError::ArithmeticOverflow)?;

        let r10_x = self.rotation[1][0]
            .checked_mul(x)
            .ok_or(ExtrinsicsError::ArithmeticOverflow)?;
        let r11_y = self.rotation[1][1]
            .checked_mul(y)
            .ok_or(ExtrinsicsError::ArithmeticOverflow)?;
        let r12_z = self.rotation[1][2]
            .checked_mul(z)
            .ok_or(ExtrinsicsError::ArithmeticOverflow)?;
        let ty = r10_x
            .checked_add(r11_y)
            .and_then(|val| val.checked_add(r12_z))
            .and_then(|val| val.checked_add(self.translation_mm[1]))
            .ok_or(ExtrinsicsError::ArithmeticOverflow)?;

        let r20_x = self.rotation[2][0]
            .checked_mul(x)
            .ok_or(ExtrinsicsError::ArithmeticOverflow)?;
        let r21_y = self.rotation[2][1]
            .checked_mul(y)
            .ok_or(ExtrinsicsError::ArithmeticOverflow)?;
        let r22_z = self.rotation[2][2]
            .checked_mul(z)
            .ok_or(ExtrinsicsError::ArithmeticOverflow)?;
        let tz = r20_x
            .checked_add(r21_y)
            .and_then(|val| val.checked_add(r22_z))
            .and_then(|val| val.checked_add(self.translation_mm[2]))
            .ok_or(ExtrinsicsError::ArithmeticOverflow)?;

        Ok([tx, ty, tz])
    }

    /// Computes the inverse transform $(R^T, -R^T \cdot T)$.
    pub fn inverse(&self) -> Result<Self, ExtrinsicsError> {
        let inv_rotation = [
            [
                self.rotation[0][0],
                self.rotation[1][0],
                self.rotation[2][0],
            ],
            [
                self.rotation[0][1],
                self.rotation[1][1],
                self.rotation[2][1],
            ],
            [
                self.rotation[0][2],
                self.rotation[1][2],
                self.rotation[2][2],
            ],
        ];

        let tx = self.translation_mm[0];
        let ty = self.translation_mm[1];
        let tz = self.translation_mm[2];

        let inv_tx = inv_rotation[0][0]
            .checked_mul(tx)
            .and_then(|a| {
                inv_rotation[0][1]
                    .checked_mul(ty)
                    .and_then(|b| a.checked_add(b))
            })
            .and_then(|a| {
                inv_rotation[0][2]
                    .checked_mul(tz)
                    .and_then(|b| a.checked_add(b))
            })
            .and_then(|val| val.0.checked_neg().map(Fixed64))
            .ok_or(ExtrinsicsError::ArithmeticOverflow)?;

        let inv_ty = inv_rotation[1][0]
            .checked_mul(tx)
            .and_then(|a| {
                inv_rotation[1][1]
                    .checked_mul(ty)
                    .and_then(|b| a.checked_add(b))
            })
            .and_then(|a| {
                inv_rotation[1][2]
                    .checked_mul(tz)
                    .and_then(|b| a.checked_add(b))
            })
            .and_then(|val| val.0.checked_neg().map(Fixed64))
            .ok_or(ExtrinsicsError::ArithmeticOverflow)?;

        let inv_tz = inv_rotation[2][0]
            .checked_mul(tx)
            .and_then(|a| {
                inv_rotation[2][1]
                    .checked_mul(ty)
                    .and_then(|b| a.checked_add(b))
            })
            .and_then(|a| {
                inv_rotation[2][2]
                    .checked_mul(tz)
                    .and_then(|b| a.checked_add(b))
            })
            .and_then(|val| val.0.checked_neg().map(Fixed64))
            .ok_or(ExtrinsicsError::ArithmeticOverflow)?;

        Ok(Self {
            rotation: inv_rotation,
            translation_mm: [inv_tx, inv_ty, inv_tz],
        })
    }
}

impl CanonicalEncode for RigidTransform3D {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        for row in &self.rotation {
            for elem in row {
                elem.encode_canonical(encoder);
            }
        }
        for elem in &self.translation_mm {
            elem.encode_canonical(encoder);
        }
    }
}

/// 6-DOF parameter covariance metrics for the fitted cross-camera rigid transform.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtrinsicsCovariance {
    /// Rotation angle parameter variances in micro-radians squared ($\mu\text{rad}^2$) for $[r_x, r_y, r_z]$.
    pub rotation_variance_urad2: [u64; 3],
    /// Translation parameter variances in micro-millimeters squared ($\mu\text{mm}^2$) for $[t_x, t_y, t_z]$.
    pub translation_variance_umm2: [u64; 3],
}

impl CanonicalEncode for ExtrinsicsCovariance {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        for v in &self.rotation_variance_urad2 {
            encoder.u64(*v);
        }
        for v in &self.translation_variance_umm2 {
            encoder.u64(*v);
        }
    }
}

/// Goodness-of-fit and reprojection residual metrics for certified cross-camera extrinsics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtrinsicsResidual {
    /// Mean 2D reprojection error across all fitted correspondences in micro-pixels.
    pub mean_reprojection_error_upx: u64,
    /// Maximum 2D reprojection error across all fitted correspondences in micro-pixels.
    pub max_reprojection_error_upx: u64,
    /// Root mean squared 2D reprojection error (RMSE) in micro-pixels.
    pub rmse_upx: u64,
    /// Root mean squared 3D point alignment error in micro-millimeters.
    pub alignment_3d_rmse_umm: u64,
    /// Estimated 6-DOF pose covariance.
    pub covariance: ExtrinsicsCovariance,
    /// Number of verified 2D-3D cross-camera correspondences fitted.
    pub correspondence_count: usize,
}

impl CanonicalEncode for ExtrinsicsResidual {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u64(self.mean_reprojection_error_upx);
        encoder.u64(self.max_reprojection_error_upx);
        encoder.u64(self.rmse_upx);
        encoder.u64(self.alignment_3d_rmse_umm);
        self.covariance.encode_canonical(encoder);
        encoder.u64(self.correspondence_count as u64);
    }
}

/// A certified cross-camera correspondence observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtrinsicsCorrespondence {
    /// Monotonic correspondence identifier.
    pub correspondence_id: u64,
    /// Physical landmark or target feature identifier.
    pub feature_id: u64,
    /// 3D landmark coordinates observed in source camera frame in millimeters $[X, Y, Z]$.
    pub source_point_mm: [i32; 3],
    /// 3D landmark coordinates observed in target camera frame in millimeters $[X, Y, Z]$.
    pub target_point_mm: [i32; 3],
    /// Observed 2D pixel coordinates $(u, v)$ in source camera image in micro-pixels.
    pub source_pixel_upx: (i64, i64),
    /// Observed 2D pixel coordinates $(u, v)$ in target camera image in micro-pixels.
    pub target_pixel_upx: (i64, i64),
    /// Timestamp when this simultaneous observation was captured.
    pub capture_time: TimestampNs,
    /// Cryptographic digest of this correspondence evidence.
    pub digest: ContentDigest,
}

impl ExtrinsicsCorrespondence {
    /// Constructs a verified cross-camera correspondence observation with cryptographic digest.
    pub fn new(
        correspondence_id: u64,
        feature_id: u64,
        source_point_mm: [i32; 3],
        target_point_mm: [i32; 3],
        source_pixel_upx: (i64, i64),
        target_pixel_upx: (i64, i64),
        capture_time: TimestampNs,
    ) -> Result<Self, ExtrinsicsError> {
        let mut encoder = CanonicalEncoder::new();
        encoder.u64(correspondence_id);
        encoder.u64(feature_id);
        encoder.i128(source_point_mm[0] as i128);
        encoder.i128(source_point_mm[1] as i128);
        encoder.i128(source_point_mm[2] as i128);
        encoder.i128(target_point_mm[0] as i128);
        encoder.i128(target_point_mm[1] as i128);
        encoder.i128(target_point_mm[2] as i128);
        encoder.i128(source_pixel_upx.0 as i128);
        encoder.i128(source_pixel_upx.1 as i128);
        encoder.i128(target_pixel_upx.0 as i128);
        encoder.i128(target_pixel_upx.1 as i128);
        encoder.i128(capture_time.0);

        let bytes = encoder
            .finish_checked()
            .map_err(ExtrinsicsError::Contract)?;
        let digest = ContentDigest::sha256(&bytes);

        Ok(Self {
            correspondence_id,
            feature_id,
            source_point_mm,
            target_point_mm,
            source_pixel_upx,
            target_pixel_upx,
            capture_time,
            digest,
        })
    }
}

impl CanonicalEncode for ExtrinsicsCorrespondence {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u64(self.correspondence_id);
        encoder.u64(self.feature_id);
        encoder.i128(self.source_point_mm[0] as i128);
        encoder.i128(self.source_point_mm[1] as i128);
        encoder.i128(self.source_point_mm[2] as i128);
        encoder.i128(self.target_point_mm[0] as i128);
        encoder.i128(self.target_point_mm[1] as i128);
        encoder.i128(self.target_point_mm[2] as i128);
        encoder.i128(self.source_pixel_upx.0 as i128);
        encoder.i128(self.source_pixel_upx.1 as i128);
        encoder.i128(self.target_pixel_upx.0 as i128);
        encoder.i128(self.target_pixel_upx.1 as i128);
        encoder.i128(self.capture_time.0);
        encoder.bytes(&self.digest.bytes());
    }
}

/// A certified, typed, immutable cross-camera extrinsics certificate (FSS-090).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtrinsicsCertificate {
    /// Certificate stable identifier string.
    pub certificate_id: String,
    /// Originating source camera device identity.
    pub source_camera: DeviceId,
    /// Destination target camera device identity.
    pub target_camera: DeviceId,
    /// Hardware device generation of the source camera.
    pub source_device_generation: DeviceGeneration,
    /// Hardware device generation of the target camera.
    pub target_device_generation: DeviceGeneration,
    /// Firmware generation of the source camera.
    pub source_firmware_generation: FirmwareGeneration,
    /// Firmware generation of the target camera.
    pub target_firmware_generation: FirmwareGeneration,
    /// Cryptographic digest of the certified source camera intrinsics.
    pub source_intrinsics_digest: ContentDigest,
    /// Cryptographic digest of the certified target camera intrinsics.
    pub target_intrinsics_digest: ContentDigest,
    /// Calibration generation of the source camera intrinsics.
    pub source_calibration_generation: CalibrationGeneration,
    /// Calibration generation of the target camera intrinsics.
    pub target_calibration_generation: CalibrationGeneration,
    /// Metric calibration generation identifier for this extrinsics certificate.
    pub calibration_generation: CalibrationGeneration,
    /// Certified rigid 3D transform $P_{\text{target}} = R \cdot P_{\text{source}} + T$.
    pub transform: RigidTransform3D,
    /// Goodness-of-fit residual and covariance metrics.
    pub residual: ExtrinsicsResidual,
    /// Certified validity time interval.
    pub validity: CaptureInterval,
    /// Retained sample evidence from which parameters were fitted.
    pub evidence: Vec<ExtrinsicsCorrespondence>,
    /// Content-addressed root digest over all correspondence evidence.
    pub evidence_root: ContentDigest,
    /// Cryptographic seal digest of the entire certificate.
    pub certificate_digest: ContentDigest,
}

impl ExtrinsicsCertificate {
    /// Validates that the certificate is currently valid at query timestamp `time`.
    pub fn validate_at_time(&self, time: TimestampNs) -> Result<(), ExtrinsicsError> {
        if time.0 < self.validity.earliest.0 || time.0 > self.validity.latest.0 {
            return Err(ExtrinsicsError::StaleCertificatePastValidity {
                requested: time,
                valid_until: self.validity.latest,
            });
        }
        Ok(())
    }

    /// Validates that the certificate strictly matches the requested camera pair.
    pub fn validate_camera_pair(
        &self,
        source: &DeviceId,
        target: &DeviceId,
    ) -> Result<(), ExtrinsicsError> {
        if &self.source_camera != source {
            return Err(ExtrinsicsError::CameraIdMismatch {
                expected: self.source_camera.clone(),
                actual: source.clone(),
            });
        }
        if &self.target_camera != target {
            return Err(ExtrinsicsError::CameraIdMismatch {
                expected: self.target_camera.clone(),
                actual: target.clone(),
            });
        }
        Ok(())
    }

    /// Validates that bound intrinsics certificates match the active runtime intrinsics.
    pub fn validate_intrinsics(
        &self,
        source_cert: &IntrinsicsCertificate,
        target_cert: &IntrinsicsCertificate,
    ) -> Result<(), ExtrinsicsError> {
        if self.source_camera != source_cert.device_id {
            return Err(ExtrinsicsError::CameraIdMismatch {
                expected: self.source_camera.clone(),
                actual: source_cert.device_id.clone(),
            });
        }
        if self.target_camera != target_cert.device_id {
            return Err(ExtrinsicsError::CameraIdMismatch {
                expected: self.target_camera.clone(),
                actual: target_cert.device_id.clone(),
            });
        }
        if self.source_intrinsics_digest != source_cert.certificate_digest {
            return Err(ExtrinsicsError::SourceIntrinsicsDigestMismatch {
                expected: self.source_intrinsics_digest,
                actual: source_cert.certificate_digest,
            });
        }
        if self.target_intrinsics_digest != target_cert.certificate_digest {
            return Err(ExtrinsicsError::TargetIntrinsicsDigestMismatch {
                expected: self.target_intrinsics_digest,
                actual: target_cert.certificate_digest,
            });
        }
        if self.source_calibration_generation != source_cert.calibration_generation {
            return Err(ExtrinsicsError::CalibrationGenerationMismatch {
                expected: self.source_calibration_generation.clone(),
                actual: source_cert.calibration_generation.clone(),
            });
        }
        if self.target_calibration_generation != target_cert.calibration_generation {
            return Err(ExtrinsicsError::CalibrationGenerationMismatch {
                expected: self.target_calibration_generation.clone(),
                actual: target_cert.calibration_generation.clone(),
            });
        }
        if self.source_device_generation != source_cert.device_generation {
            return Err(ExtrinsicsError::SourceDeviceGenerationMismatch {
                expected: self.source_device_generation.clone(),
                actual: source_cert.device_generation.clone(),
            });
        }
        if self.target_device_generation != target_cert.device_generation {
            return Err(ExtrinsicsError::TargetDeviceGenerationMismatch {
                expected: self.target_device_generation.clone(),
                actual: target_cert.device_generation.clone(),
            });
        }
        if self.source_firmware_generation != source_cert.firmware_generation {
            return Err(ExtrinsicsError::SourceFirmwareGenerationMismatch {
                expected: self.source_firmware_generation.clone(),
                actual: source_cert.firmware_generation.clone(),
            });
        }
        if self.target_firmware_generation != target_cert.firmware_generation {
            return Err(ExtrinsicsError::TargetFirmwareGenerationMismatch {
                expected: self.target_firmware_generation.clone(),
                actual: target_cert.firmware_generation.clone(),
            });
        }
        Ok(())
    }

    /// Evaluates the 2D reprojection error of a correspondence against target camera intrinsics.
    pub fn evaluate_correspondence_error(
        &self,
        corr: &ExtrinsicsCorrespondence,
        target_intrinsics: &CameraIntrinsics,
    ) -> Result<u64, ExtrinsicsError> {
        let p_source = [
            corr.source_point_mm[0] as f64,
            corr.source_point_mm[1] as f64,
            corr.source_point_mm[2] as f64,
        ];

        let p_target = self.transform.transform_point_f64(p_source);
        if p_target[2] <= 1e-6 {
            return Err(ExtrinsicsError::InvalidTransform(
                "transformed 3D point is on or behind the target camera optical plane (Z <= 0)"
                    .to_string(),
            ));
        }

        // Validate 3D landmark deviation does not contradict estimated rigid pose
        let dx3 = p_target[0] - (corr.target_point_mm[0] as f64);
        let dy3 = p_target[1] - (corr.target_point_mm[1] as f64);
        let dz3 = p_target[2] - (corr.target_point_mm[2] as f64);
        let dist_3d_mm = (dx3 * dx3 + dy3 * dy3 + dz3 * dz3).sqrt();
        let max_allowed_3d_mm =
            ((self.residual.alignment_3d_rmse_umm as f64) / 1000.0).max(100.0) * 3.0;
        if dist_3d_mm > max_allowed_3d_mm {
            return Err(ExtrinsicsError::ContradictedExtrinsics {
                correspondence_id: corr.correspondence_id,
                observed_error_upx: (dist_3d_mm * (MICRO_UNIT_SCALE as f64)).round() as u64,
                tolerance_upx: (max_allowed_3d_mm * (MICRO_UNIT_SCALE as f64)).round() as u64,
            });
        }

        let proj = target_intrinsics
            .project_point_f64(p_target)
            .map_err(ExtrinsicsError::IntrinsicsError)?;

        let u_proj_upx = (proj[0] * (MICRO_UNIT_SCALE as f64)).round() as i64;
        let v_proj_upx = (proj[1] * (MICRO_UNIT_SCALE as f64)).round() as i64;

        let du = corr
            .target_pixel_upx
            .0
            .checked_sub(u_proj_upx)
            .ok_or(ExtrinsicsError::ArithmeticOverflow)?;
        let dv = corr
            .target_pixel_upx
            .1
            .checked_sub(v_proj_upx)
            .ok_or(ExtrinsicsError::ArithmeticOverflow)?;

        let du_f = du as f64;
        let dv_f = dv as f64;
        let dist = (du_f * du_f + dv_f * dv_f).sqrt();
        Ok(dist.round() as u64)
    }

    /// Verifies that a new correspondence observation does not contradict this certified extrinsics.
    pub fn verify_not_contradicted(
        &self,
        corr: &ExtrinsicsCorrespondence,
        target_intrinsics: &CameraIntrinsics,
        tolerance_upx: u64,
    ) -> Result<(), ExtrinsicsError> {
        let err_upx = self.evaluate_correspondence_error(corr, target_intrinsics)?;
        if err_upx > tolerance_upx {
            return Err(ExtrinsicsError::ContradictedExtrinsics {
                correspondence_id: corr.correspondence_id,
                observed_error_upx: err_upx,
                tolerance_upx,
            });
        }
        Ok(())
    }

    /// Computes canonical binary encoding bytes for this certificate.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ExtrinsicsError> {
        let mut encoder = CanonicalEncoder::new();
        self.encode_canonical(&mut encoder);
        encoder.finish_checked().map_err(ExtrinsicsError::Contract)
    }
}

impl CanonicalEncode for ExtrinsicsCertificate {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.certificate_id);
        encoder.text(self.source_camera.as_str());
        encoder.text(self.target_camera.as_str());
        encoder.text(self.source_device_generation.as_str());
        encoder.text(self.target_device_generation.as_str());
        encoder.text(self.source_firmware_generation.as_str());
        encoder.text(self.target_firmware_generation.as_str());
        encoder.bytes(&self.source_intrinsics_digest.bytes());
        encoder.bytes(&self.target_intrinsics_digest.bytes());
        encoder.text(self.source_calibration_generation.as_str());
        encoder.text(self.target_calibration_generation.as_str());
        encoder.text(self.calibration_generation.as_str());
        self.transform.encode_canonical(encoder);
        self.residual.encode_canonical(encoder);
        encoder.i128(self.validity.earliest.0);
        encoder.i128(self.validity.latest.0);
        encoder.bytes(&self.evidence_root.bytes());
        encoder.u64(self.evidence.len() as u64);
        for c in &self.evidence {
            c.encode_canonical(encoder);
        }
    }
}

/// Builder for constructing and sealing an [`ExtrinsicsCertificate`].
#[derive(Clone, Debug)]
pub struct ExtrinsicsCertificateBuilder {
    certificate_id: String,
    source_camera: Option<DeviceId>,
    target_camera: Option<DeviceId>,
    source_device_generation: Option<DeviceGeneration>,
    target_device_generation: Option<DeviceGeneration>,
    source_firmware_generation: Option<FirmwareGeneration>,
    target_firmware_generation: Option<FirmwareGeneration>,
    source_intrinsics_digest: Option<ContentDigest>,
    target_intrinsics_digest: Option<ContentDigest>,
    source_calibration_generation: Option<CalibrationGeneration>,
    target_calibration_generation: Option<CalibrationGeneration>,
    calibration_generation: Option<CalibrationGeneration>,
    transform: Option<RigidTransform3D>,
    residual: Option<ExtrinsicsResidual>,
    validity: Option<CaptureInterval>,
    evidence: Option<Vec<ExtrinsicsCorrespondence>>,
}

impl ExtrinsicsCertificateBuilder {
    /// Creates a new builder with the specified certificate identifier.
    pub fn new(certificate_id: &str) -> Result<Self, ExtrinsicsError> {
        if certificate_id.is_empty() {
            return Err(ExtrinsicsError::EmptyCertificateId);
        }
        if certificate_id.len() > MAX_CERTIFICATE_ID_BYTES {
            return Err(ExtrinsicsError::CertificateIdTooLong {
                actual: certificate_id.len(),
                max: MAX_CERTIFICATE_ID_BYTES,
            });
        }
        Ok(Self {
            certificate_id: certificate_id.to_string(),
            source_camera: None,
            target_camera: None,
            source_device_generation: None,
            target_device_generation: None,
            source_firmware_generation: None,
            target_firmware_generation: None,
            source_intrinsics_digest: None,
            target_intrinsics_digest: None,
            source_calibration_generation: None,
            target_calibration_generation: None,
            calibration_generation: None,
            transform: None,
            residual: None,
            validity: None,
            evidence: None,
        })
    }

    /// Sets the source and target camera device identifiers.
    #[must_use]
    pub fn camera_pair(mut self, source: DeviceId, target: DeviceId) -> Self {
        self.source_camera = Some(source);
        self.target_camera = Some(target);
        self
    }

    /// Sets source camera bindings.
    #[must_use]
    pub fn source_binding(
        mut self,
        device_generation: DeviceGeneration,
        firmware_generation: FirmwareGeneration,
        intrinsics_digest: ContentDigest,
        calibration_generation: CalibrationGeneration,
    ) -> Self {
        self.source_device_generation = Some(device_generation);
        self.source_firmware_generation = Some(firmware_generation);
        self.source_intrinsics_digest = Some(intrinsics_digest);
        self.source_calibration_generation = Some(calibration_generation);
        self
    }

    /// Sets target camera bindings.
    #[must_use]
    pub fn target_binding(
        mut self,
        device_generation: DeviceGeneration,
        firmware_generation: FirmwareGeneration,
        intrinsics_digest: ContentDigest,
        calibration_generation: CalibrationGeneration,
    ) -> Self {
        self.target_device_generation = Some(device_generation);
        self.target_firmware_generation = Some(firmware_generation);
        self.target_intrinsics_digest = Some(intrinsics_digest);
        self.target_calibration_generation = Some(calibration_generation);
        self
    }

    /// Sets extrinsics calibration generation.
    #[must_use]
    pub fn calibration_generation(mut self, cal_gen: CalibrationGeneration) -> Self {
        self.calibration_generation = Some(cal_gen);
        self
    }

    /// Sets the rigid 3D transform.
    #[must_use]
    pub fn transform(mut self, transform: RigidTransform3D) -> Self {
        self.transform = Some(transform);
        self
    }

    /// Sets residual metrics.
    #[must_use]
    pub fn residual(mut self, residual: ExtrinsicsResidual) -> Self {
        self.residual = Some(residual);
        self
    }

    /// Sets validity interval.
    #[must_use]
    pub fn validity(mut self, validity: CaptureInterval) -> Self {
        self.validity = Some(validity);
        self
    }

    /// Sets correspondence evidence samples.
    pub fn evidence(
        mut self,
        evidence: Vec<ExtrinsicsCorrespondence>,
    ) -> Result<Self, ExtrinsicsError> {
        if evidence.len() < MIN_EXTRINSICS_CORRESPONDENCES {
            return Err(ExtrinsicsError::InsufficientCorrespondences {
                count: evidence.len(),
                min_required: MIN_EXTRINSICS_CORRESPONDENCES,
            });
        }
        if evidence.len() > MAX_EXTRINSICS_CORRESPONDENCES {
            return Err(ExtrinsicsError::TooManyCorrespondences {
                actual: evidence.len(),
                max: MAX_EXTRINSICS_CORRESPONDENCES,
            });
        }
        self.evidence = Some(evidence);
        Ok(self)
    }

    /// Validates all constraints and constructs the sealed, immutable extrinsics certificate.
    pub fn build(self) -> Result<ExtrinsicsCertificate, ExtrinsicsError> {
        let source_camera = self.source_camera.ok_or_else(|| {
            ExtrinsicsError::InvalidTransform("missing source_camera".to_string())
        })?;
        let target_camera = self.target_camera.ok_or_else(|| {
            ExtrinsicsError::InvalidTransform("missing target_camera".to_string())
        })?;

        // 1. Invariant: Camera pair must be distinct physical devices
        if source_camera == target_camera {
            return Err(ExtrinsicsError::IdenticalCameraPair {
                camera: source_camera,
            });
        }

        let source_device_generation = self.source_device_generation.ok_or_else(|| {
            ExtrinsicsError::InvalidTransform("missing source_device_generation".to_string())
        })?;
        let target_device_generation = self.target_device_generation.ok_or_else(|| {
            ExtrinsicsError::InvalidTransform("missing target_device_generation".to_string())
        })?;
        let source_firmware_generation = self.source_firmware_generation.ok_or_else(|| {
            ExtrinsicsError::InvalidTransform("missing source_firmware_generation".to_string())
        })?;
        let target_firmware_generation = self.target_firmware_generation.ok_or_else(|| {
            ExtrinsicsError::InvalidTransform("missing target_firmware_generation".to_string())
        })?;
        let source_intrinsics_digest = self.source_intrinsics_digest.ok_or_else(|| {
            ExtrinsicsError::InvalidTransform("missing source_intrinsics_digest".to_string())
        })?;
        let target_intrinsics_digest = self.target_intrinsics_digest.ok_or_else(|| {
            ExtrinsicsError::InvalidTransform("missing target_intrinsics_digest".to_string())
        })?;
        let source_calibration_generation =
            self.source_calibration_generation.ok_or_else(|| {
                ExtrinsicsError::InvalidTransform(
                    "missing source_calibration_generation".to_string(),
                )
            })?;
        let target_calibration_generation =
            self.target_calibration_generation.ok_or_else(|| {
                ExtrinsicsError::InvalidTransform(
                    "missing target_calibration_generation".to_string(),
                )
            })?;
        let calibration_generation = self.calibration_generation.ok_or_else(|| {
            ExtrinsicsError::InvalidTransform("missing calibration_generation".to_string())
        })?;
        let transform = self
            .transform
            .ok_or_else(|| ExtrinsicsError::InvalidTransform("missing transform".to_string()))?;
        let residual = self
            .residual
            .ok_or_else(|| ExtrinsicsError::InvalidTransform("missing residual".to_string()))?;
        let validity = self
            .validity
            .ok_or_else(|| ExtrinsicsError::InvalidTransform("missing validity".to_string()))?;
        let evidence = self
            .evidence
            .ok_or_else(|| ExtrinsicsError::InvalidTransform("missing evidence".to_string()))?;

        // 2. Invariant: Transform must be non-identity and orthogonal
        if transform.is_identity() {
            return Err(ExtrinsicsError::IdentityTransformProhibited);
        }
        transform.validate_orthogonality()?;

        // 3. Invariant: Residual RMSE must not exceed declared tolerance bound
        if residual.rmse_upx > MAX_EXTRINSICS_REPROJECTION_TOLERANCE_UPX {
            return Err(ExtrinsicsError::ResidualExceedsTolerance {
                actual_rmse_upx: residual.rmse_upx,
                max_allowed_upx: MAX_EXTRINSICS_REPROJECTION_TOLERANCE_UPX,
            });
        }

        // 4. Invariant: Evidence must not be degenerate
        validate_non_degenerate_correspondences(&evidence)?;

        // 5. Merkle root of correspondence evidence digests
        let mut evidence_bytes = Vec::new();
        for c in &evidence {
            evidence_bytes.extend_from_slice(&c.digest.bytes());
        }
        let evidence_root = ContentDigest::sha256(&evidence_bytes);

        // 6. Seal certificate digest directly over canonical binary representation
        let mut cert = ExtrinsicsCertificate {
            certificate_id: self.certificate_id,
            source_camera,
            target_camera,
            source_device_generation,
            target_device_generation,
            source_firmware_generation,
            target_firmware_generation,
            source_intrinsics_digest,
            target_intrinsics_digest,
            source_calibration_generation,
            target_calibration_generation,
            calibration_generation,
            transform,
            residual,
            validity,
            evidence,
            evidence_root,
            certificate_digest: ContentDigest::sha256(b"placeholder"),
        };

        let bytes = cert.canonical_bytes()?;
        cert.certificate_digest = ContentDigest::sha256(&bytes);

        Ok(cert)
    }
}

/// Checks that correspondence points form a non-degenerate 3D geometric configuration.
fn validate_non_degenerate_correspondences(
    evidence: &[ExtrinsicsCorrespondence],
) -> Result<(), ExtrinsicsError> {
    if evidence.len() < MIN_EXTRINSICS_CORRESPONDENCES {
        return Err(ExtrinsicsError::InsufficientCorrespondences {
            count: evidence.len(),
            min_required: MIN_EXTRINSICS_CORRESPONDENCES,
        });
    }

    // 1. Enforce strictly positive depth Z > 0 for all points in both frames
    for c in evidence {
        if c.source_point_mm[2] <= 0 {
            return Err(ExtrinsicsError::DegenerateCorrespondences {
                reason: format!(
                    "source correspondence point {} has non-positive depth Z = {} mm (Z > 0 required)",
                    c.correspondence_id, c.source_point_mm[2]
                ),
            });
        }
        if c.target_point_mm[2] <= 0 {
            return Err(ExtrinsicsError::DegenerateCorrespondences {
                reason: format!(
                    "target correspondence point {} has non-positive depth Z = {} mm (Z > 0 required)",
                    c.correspondence_id, c.target_point_mm[2]
                ),
            });
        }
    }

    // 2. Enforce minimum distinct 3D points in source and target frames (>= 8)
    let mut distinct_src = BTreeSet::new();
    let mut distinct_tgt = BTreeSet::new();
    for c in evidence {
        distinct_src.insert(c.source_point_mm);
        distinct_tgt.insert(c.target_point_mm);
    }
    if distinct_src.len() < MIN_EXTRINSICS_CORRESPONDENCES {
        return Err(ExtrinsicsError::DegenerateCorrespondences {
            reason: format!(
                "insufficient distinct source 3D points: {} distinct points provided, minimum {} required",
                distinct_src.len(),
                MIN_EXTRINSICS_CORRESPONDENCES
            ),
        });
    }
    if distinct_tgt.len() < MIN_EXTRINSICS_CORRESPONDENCES {
        return Err(ExtrinsicsError::DegenerateCorrespondences {
            reason: format!(
                "insufficient distinct target 3D points: {} distinct points provided, minimum {} required",
                distinct_tgt.len(),
                MIN_EXTRINSICS_CORRESPONDENCES
            ),
        });
    }

    // 3. Check 3D non-collinearity of source points using cross products
    let mut max_src_d2 = 0i128;
    let mut idx_src_a = 0;
    let mut idx_src_b = 0;
    for i in 0..evidence.len() {
        for j in (i + 1)..evidence.len() {
            let dx = (evidence[i].source_point_mm[0] - evidence[j].source_point_mm[0]) as i128;
            let dy = (evidence[i].source_point_mm[1] - evidence[j].source_point_mm[1]) as i128;
            let dz = (evidence[i].source_point_mm[2] - evidence[j].source_point_mm[2]) as i128;
            let d2 = dx * dx + dy * dy + dz * dz;
            if d2 > max_src_d2 {
                max_src_d2 = d2;
                idx_src_a = i;
                idx_src_b = j;
            }
        }
    }

    let min_spread_sq: i128 = (MIN_SPATIAL_SPREAD_MM as i128) * (MIN_SPATIAL_SPREAD_MM as i128);

    // Minimum 3D span: 10mm (10^2 = 100 mm^2)
    if max_src_d2 < min_spread_sq {
        return Err(ExtrinsicsError::DegenerateCorrespondences {
            reason: format!(
                "source correspondence points have insufficient 3D spatial spread (< {}mm)",
                MIN_SPATIAL_SPREAD_MM
            ),
        });
    }

    let p_src_a = evidence[idx_src_a].source_point_mm;
    let p_src_b = evidence[idx_src_b].source_point_mm;
    let vx = (p_src_b[0] - p_src_a[0]) as i128;
    let vy = (p_src_b[1] - p_src_a[1]) as i128;
    let vz = (p_src_b[2] - p_src_a[2]) as i128;

    let mut max_src_perp_d2 = 0i128;
    for c in evidence {
        let ux = (c.source_point_mm[0] - p_src_a[0]) as i128;
        let uy = (c.source_point_mm[1] - p_src_a[1]) as i128;
        let uz = (c.source_point_mm[2] - p_src_a[2]) as i128;

        let wx = uy * vz - uz * vy;
        let wy = uz * vx - ux * vz;
        let wz = ux * vy - uy * vx;

        let cross_sq = wx * wx + wy * wy + wz * wz;
        let perp_d2 = cross_sq / max_src_d2;
        if perp_d2 > max_src_perp_d2 {
            max_src_perp_d2 = perp_d2;
        }
    }

    if max_src_perp_d2 < min_spread_sq {
        return Err(ExtrinsicsError::DegenerateCorrespondences {
            reason: format!(
                "source correspondence points are collinear in 3D: perpendicular deviation from line < {}mm",
                MIN_SPATIAL_SPREAD_MM
            ),
        });
    }

    // 4. Check 3D non-collinearity of target points using cross products
    let mut max_tgt_d2 = 0i128;
    let mut idx_tgt_a = 0;
    let mut idx_tgt_b = 0;
    for i in 0..evidence.len() {
        for j in (i + 1)..evidence.len() {
            let dx = (evidence[i].target_point_mm[0] - evidence[j].target_point_mm[0]) as i128;
            let dy = (evidence[i].target_point_mm[1] - evidence[j].target_point_mm[1]) as i128;
            let dz = (evidence[i].target_point_mm[2] - evidence[j].target_point_mm[2]) as i128;
            let d2 = dx * dx + dy * dy + dz * dz;
            if d2 > max_tgt_d2 {
                max_tgt_d2 = d2;
                idx_tgt_a = i;
                idx_tgt_b = j;
            }
        }
    }

    if max_tgt_d2 < min_spread_sq {
        return Err(ExtrinsicsError::DegenerateCorrespondences {
            reason: format!(
                "target correspondence points have insufficient 3D spatial spread (< {}mm)",
                MIN_SPATIAL_SPREAD_MM
            ),
        });
    }

    let p_tgt_a = evidence[idx_tgt_a].target_point_mm;
    let p_tgt_b = evidence[idx_tgt_b].target_point_mm;
    let tvx = (p_tgt_b[0] - p_tgt_a[0]) as i128;
    let tvy = (p_tgt_b[1] - p_tgt_a[1]) as i128;
    let tvz = (p_tgt_b[2] - p_tgt_a[2]) as i128;

    let mut max_tgt_perp_d2 = 0i128;
    for c in evidence {
        let tux = (c.target_point_mm[0] - p_tgt_a[0]) as i128;
        let tuy = (c.target_point_mm[1] - p_tgt_a[1]) as i128;
        let tuz = (c.target_point_mm[2] - p_tgt_a[2]) as i128;

        let twx = tuy * tvz - tuz * tvy;
        let twy = tuz * tvx - tux * tvz;
        let twz = tux * tvy - tuy * tvx;

        let cross_sq = twx * twx + twy * twy + twz * twz;
        let perp_d2 = cross_sq / max_tgt_d2;
        if perp_d2 > max_tgt_perp_d2 {
            max_tgt_perp_d2 = perp_d2;
        }
    }

    if max_tgt_perp_d2 < min_spread_sq {
        return Err(ExtrinsicsError::DegenerateCorrespondences {
            reason: format!(
                "target correspondence points are collinear in 3D: perpendicular deviation from line < {}mm",
                MIN_SPATIAL_SPREAD_MM
            ),
        });
    }

    Ok(())
}

/// Request parameters for solving cross-camera extrinsics.
#[derive(Clone, Debug)]
pub struct ExtrinsicsSolveRequest<'a> {
    /// Certificate identifier for the generated certificate.
    pub certificate_id: String,
    /// Certified source camera intrinsics.
    pub source_certificate: &'a IntrinsicsCertificate,
    /// Certified target camera intrinsics.
    pub target_certificate: &'a IntrinsicsCertificate,
    /// Verified cross-camera correspondence points.
    pub correspondences: Vec<ExtrinsicsCorrespondence>,
    /// Time validity interval.
    pub validity: CaptureInterval,
    /// Extrinsics calibration generation identifier.
    pub calibration_generation: CalibrationGeneration,
    /// Maximum acceptable RMS reprojection error in micro-pixels.
    pub max_reprojection_tolerance_upx: u64,
}

/// Cross-camera extrinsics solver interface.
pub trait ExtrinsicsSolver {
    /// Solves the rigid $SE(3)$ transformation between camera frames given correspondence evidence.
    fn solve(
        &self,
        request: &ExtrinsicsSolveRequest<'_>,
    ) -> Result<ExtrinsicsCertificate, ExtrinsicsError>;
}

/// Deterministic reference solver for cross-camera extrinsics using Horn's absolute orientation algorithm.
///
/// Implements closed-form orientation via quaternion eigensolver with Jacobi diagonalization.
/// Evaluated using deterministic IEEE 754-2008 arithmetic and fixed-point [`Fixed64`] conversion.
#[derive(Clone, Copy, Debug, Default)]
pub struct ReferenceExtrinsicsSolver;

impl ReferenceExtrinsicsSolver {
    /// Creates a new reference solver.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl ExtrinsicsSolver for ReferenceExtrinsicsSolver {
    fn solve(
        &self,
        request: &ExtrinsicsSolveRequest<'_>,
    ) -> Result<ExtrinsicsCertificate, ExtrinsicsError> {
        solve_extrinsics(request)
    }
}

/// Solves cross-camera extrinsics using deterministic Horn closed-form absolute orientation.
pub fn solve_extrinsics(
    request: &ExtrinsicsSolveRequest<'_>,
) -> Result<ExtrinsicsCertificate, ExtrinsicsError> {
    // 1. Invariant: Camera pair must be distinct
    if request.source_certificate.device_id == request.target_certificate.device_id {
        return Err(ExtrinsicsError::IdenticalCameraPair {
            camera: request.source_certificate.device_id.clone(),
        });
    }

    // 2. Invariant: Tolerance must not exceed system maximum bound
    if request.max_reprojection_tolerance_upx > MAX_EXTRINSICS_REPROJECTION_TOLERANCE_UPX {
        return Err(ExtrinsicsError::ResidualExceedsTolerance {
            actual_rmse_upx: request.max_reprojection_tolerance_upx,
            max_allowed_upx: MAX_EXTRINSICS_REPROJECTION_TOLERANCE_UPX,
        });
    }

    // 3. Invariant: Request validity must fall within source and target intrinsics certificate validity
    if request.validity.earliest.0 < request.source_certificate.validity.earliest.0
        || request.validity.latest.0 > request.source_certificate.validity.latest.0
    {
        return Err(ExtrinsicsError::StaleCertificatePastValidity {
            requested: request.validity.earliest,
            valid_until: request.source_certificate.validity.latest,
        });
    }
    if request.validity.earliest.0 < request.target_certificate.validity.earliest.0
        || request.validity.latest.0 > request.target_certificate.validity.latest.0
    {
        return Err(ExtrinsicsError::StaleCertificatePastValidity {
            requested: request.validity.earliest,
            valid_until: request.target_certificate.validity.latest,
        });
    }

    // 4. Invariant: All correspondence capture timestamps must fall within request validity
    for c in &request.correspondences {
        if c.capture_time.0 < request.validity.earliest.0
            || c.capture_time.0 > request.validity.latest.0
        {
            return Err(ExtrinsicsError::StaleCertificatePastValidity {
                requested: c.capture_time,
                valid_until: request.validity.latest,
            });
        }
    }

    // 5. Invariant: Correspondence count bounds
    let count = request.correspondences.len();
    if count < MIN_EXTRINSICS_CORRESPONDENCES {
        return Err(ExtrinsicsError::InsufficientCorrespondences {
            count,
            min_required: MIN_EXTRINSICS_CORRESPONDENCES,
        });
    }
    if count > MAX_EXTRINSICS_CORRESPONDENCES {
        return Err(ExtrinsicsError::TooManyCorrespondences {
            actual: count,
            max: MAX_EXTRINSICS_CORRESPONDENCES,
        });
    }

    // 6. Invariant: Non-degenerate spatial distribution
    validate_non_degenerate_correspondences(&request.correspondences)?;

    // 4. Compute centroids of source and target 3D points
    let n = count as f64;
    let mut p_src_sum = [0.0_f64; 3];
    let mut p_tgt_sum = [0.0_f64; 3];

    for c in &request.correspondences {
        p_src_sum[0] += c.source_point_mm[0] as f64;
        p_src_sum[1] += c.source_point_mm[1] as f64;
        p_src_sum[2] += c.source_point_mm[2] as f64;

        p_tgt_sum[0] += c.target_point_mm[0] as f64;
        p_tgt_sum[1] += c.target_point_mm[1] as f64;
        p_tgt_sum[2] += c.target_point_mm[2] as f64;
    }

    let p_src_mean = [p_src_sum[0] / n, p_src_sum[1] / n, p_src_sum[2] / n];
    let p_tgt_mean = [p_tgt_sum[0] / n, p_tgt_sum[1] / n, p_tgt_sum[2] / n];

    // 5. Cross-covariance matrix H = sum_i (P_source,i - mean_source) * (P_target,i - mean_target)^T
    let mut h = [[0.0_f64; 3]; 3];
    let mut var_src = 0.0_f64;

    for c in &request.correspondences {
        let xs = (c.source_point_mm[0] as f64) - p_src_mean[0];
        let ys = (c.source_point_mm[1] as f64) - p_src_mean[1];
        let zs = (c.source_point_mm[2] as f64) - p_src_mean[2];

        let xt = (c.target_point_mm[0] as f64) - p_tgt_mean[0];
        let yt = (c.target_point_mm[1] as f64) - p_tgt_mean[1];
        let zt = (c.target_point_mm[2] as f64) - p_tgt_mean[2];

        h[0][0] += xs * xt;
        h[0][1] += xs * yt;
        h[0][2] += xs * zt;

        h[1][0] += ys * xt;
        h[1][1] += ys * yt;
        h[1][2] += ys * zt;

        h[2][0] += zs * xt;
        h[2][2] += zs * zt;
        h[2][1] += zs * yt;

        var_src += xs * xs + ys * ys + zs * zs;
    }

    // 6. Build Horn 4x4 matrix N
    let trace_h = h[0][0] + h[1][1] + h[2][2];
    let delta = [
        h[1][2] - h[2][1], // S_yz - S_zy
        h[2][0] - h[0][2], // S_zx - S_xz
        h[0][1] - h[1][0], // S_xy - S_yx
    ];

    let mut mat_n = [[0.0_f64; 4]; 4];
    mat_n[0][0] = trace_h;
    mat_n[0][1] = delta[0];
    mat_n[0][2] = delta[1];
    mat_n[0][3] = delta[2];

    mat_n[1][0] = delta[0];
    mat_n[1][1] = h[0][0] - h[1][1] - h[2][2];
    mat_n[1][2] = h[0][1] + h[1][0];
    mat_n[1][3] = h[0][2] + h[2][0];

    mat_n[2][0] = delta[1];
    mat_n[2][1] = h[0][1] + h[1][0];
    mat_n[2][2] = -h[0][0] + h[1][1] - h[2][2];
    mat_n[2][3] = h[1][2] + h[2][1];

    mat_n[3][0] = delta[2];
    mat_n[3][1] = h[0][2] + h[2][0];
    mat_n[3][2] = h[1][2] + h[2][1];
    mat_n[3][3] = -h[0][0] - h[1][1] + h[2][2];

    // 7. Solve maximum eigenvector via Jacobi diagonalization
    let (_max_eval, q) = jacobi_eigen_4x4(&mat_n)?;

    // 8. Convert optimal quaternion [w, x, y, z] to 3x3 rotation matrix
    let w = q[0];
    let x = q[1];
    let y = q[2];
    let z = q[3];

    let r_f64 = [
        [
            1.0 - 2.0 * (y * y + z * z),
            2.0 * (x * y - w * z),
            2.0 * (x * z + w * y),
        ],
        [
            2.0 * (x * y + w * z),
            1.0 - 2.0 * (x * x + z * z),
            2.0 * (y * z - w * x),
        ],
        [
            2.0 * (x * z - w * y),
            2.0 * (y * z + w * x),
            1.0 - 2.0 * (x * x + y * y),
        ],
    ];

    // 9. Translation vector T = mean_target - R * mean_source
    let t_f64 = [
        p_tgt_mean[0]
            - (r_f64[0][0] * p_src_mean[0]
                + r_f64[0][1] * p_src_mean[1]
                + r_f64[0][2] * p_src_mean[2]),
        p_tgt_mean[1]
            - (r_f64[1][0] * p_src_mean[0]
                + r_f64[1][1] * p_src_mean[1]
                + r_f64[1][2] * p_src_mean[2]),
        p_tgt_mean[2]
            - (r_f64[2][0] * p_src_mean[0]
                + r_f64[2][1] * p_src_mean[1]
                + r_f64[2][2] * p_src_mean[2]),
    ];

    let transform = RigidTransform3D::from_f64_parts(r_f64, t_f64)?;

    // 10. Prohibit uncalibrated identity
    if transform.is_identity() {
        return Err(ExtrinsicsError::IdentityTransformProhibited);
    }

    // 11. Compute residual metrics and reprojection errors
    let mut sum_err_sq_upx = 0.0_f64;
    let mut sum_err_upx = 0.0_f64;
    let mut max_err_upx = 0_u64;
    let mut sum_3d_dist_sq_umm = 0.0_f64;

    for c in &request.correspondences {
        let p_src = [
            c.source_point_mm[0] as f64,
            c.source_point_mm[1] as f64,
            c.source_point_mm[2] as f64,
        ];
        let p_pred_tgt = transform.transform_point_f64(p_src);

        // 3D error
        let dx3 = p_pred_tgt[0] - (c.target_point_mm[0] as f64);
        let dy3 = p_pred_tgt[1] - (c.target_point_mm[1] as f64);
        let dz3 = p_pred_tgt[2] - (c.target_point_mm[2] as f64);
        let dist_3d_mm = (dx3 * dx3 + dy3 * dy3 + dz3 * dz3).sqrt();
        let dist_3d_umm = dist_3d_mm * 1000.0;
        sum_3d_dist_sq_umm += dist_3d_umm * dist_3d_umm;

        // 2D reprojection error
        if p_pred_tgt[2] <= 1e-6 {
            return Err(ExtrinsicsError::InvalidTransform(
                "3D point projected behind camera plane".to_string(),
            ));
        }

        let proj = request
            .target_certificate
            .intrinsics
            .project_point_f64(p_pred_tgt)
            .map_err(ExtrinsicsError::IntrinsicsError)?;

        let u_proj_upx = (proj[0] * (MICRO_UNIT_SCALE as f64)).round() as i64;
        let v_proj_upx = (proj[1] * (MICRO_UNIT_SCALE as f64)).round() as i64;

        let du = (c.target_pixel_upx.0 - u_proj_upx) as f64;
        let dv = (c.target_pixel_upx.1 - v_proj_upx) as f64;
        let err_upx = (du * du + dv * dv).sqrt().round() as u64;

        sum_err_upx += err_upx as f64;
        sum_err_sq_upx += (err_upx as f64) * (err_upx as f64);
        max_err_upx = max_err_upx.max(err_upx);
    }

    let mean_reprojection_error_upx = (sum_err_upx / n).round() as u64;
    let rmse_upx = (sum_err_sq_upx / n).sqrt().round() as u64;
    let alignment_3d_rmse_umm = (sum_3d_dist_sq_umm / n).sqrt().round() as u64;

    // 12. Enforce tolerance bounds
    if rmse_upx > request.max_reprojection_tolerance_upx {
        return Err(ExtrinsicsError::ResidualExceedsTolerance {
            actual_rmse_upx: rmse_upx,
            max_allowed_upx: request.max_reprojection_tolerance_upx,
        });
    }

    // 13. Estimate parameter covariance
    let res_var_upx2 = sum_err_sq_upx / (n.max(7.0) - 6.0);
    let scale_rot = if var_src > 1e-6 {
        (res_var_upx2 / var_src).min(1e12)
    } else {
        1000.0
    };
    let scale_trans = (res_var_upx2 / n).min(1e12);

    let covariance = ExtrinsicsCovariance {
        rotation_variance_urad2: [
            scale_rot.round() as u64,
            scale_rot.round() as u64,
            scale_rot.round() as u64,
        ],
        translation_variance_umm2: [
            scale_trans.round() as u64,
            scale_trans.round() as u64,
            scale_trans.round() as u64,
        ],
    };

    let residual = ExtrinsicsResidual {
        mean_reprojection_error_upx,
        max_reprojection_error_upx: max_err_upx,
        rmse_upx,
        alignment_3d_rmse_umm,
        covariance,
        correspondence_count: count,
    };

    // 14. Build sealed certificate
    ExtrinsicsCertificateBuilder::new(&request.certificate_id)?
        .camera_pair(
            request.source_certificate.device_id.clone(),
            request.target_certificate.device_id.clone(),
        )
        .source_binding(
            request.source_certificate.device_generation.clone(),
            request.source_certificate.firmware_generation.clone(),
            request.source_certificate.certificate_digest,
            request.source_certificate.calibration_generation.clone(),
        )
        .target_binding(
            request.target_certificate.device_generation.clone(),
            request.target_certificate.firmware_generation.clone(),
            request.target_certificate.certificate_digest,
            request.target_certificate.calibration_generation.clone(),
        )
        .calibration_generation(request.calibration_generation.clone())
        .transform(transform)
        .residual(residual)
        .validity(request.validity)
        .evidence(request.correspondences.clone())?
        .build()
}

/// Deterministic 4x4 Jacobi real symmetric eigensolver.
fn jacobi_eigen_4x4(matrix: &[[f64; 4]; 4]) -> Result<(f64, [f64; 4]), ExtrinsicsError> {
    let mut a = *matrix;
    let mut v = [
        [1.0, 0.0, 0.0, 0.0],
        [0.0, 1.0, 0.0, 0.0],
        [0.0, 0.0, 1.0, 0.0],
        [0.0, 0.0, 0.0, 1.0],
    ];

    const MAX_SWEEPS: usize = 50;
    const EPSILON: f64 = 1e-15;

    for _ in 0..MAX_SWEEPS {
        let mut max_offdiag = 0.0_f64;
        for (i, row) in a.iter().enumerate() {
            for val in row.iter().skip(i + 1) {
                let abs_val = val.abs();
                if abs_val > max_offdiag {
                    max_offdiag = abs_val;
                }
            }
        }

        if max_offdiag < EPSILON {
            break;
        }

        for p in 0..3 {
            for q in (p + 1)..4 {
                let apq = a[p][q];
                if apq.abs() < EPSILON {
                    continue;
                }

                let app = a[p][p];
                let aqq = a[q][q];
                let theta = (aqq - app) / (2.0 * apq);
                let t = if theta >= 0.0 {
                    1.0 / (theta + (1.0 + theta * theta).sqrt())
                } else {
                    -1.0 / (-theta + (1.0 + theta * theta).sqrt())
                };

                let c = 1.0 / (1.0 + t * t).sqrt();
                let s = t * c;
                let tau = s / (1.0 + c);

                a[p][p] = app - t * apq;
                a[q][q] = aqq + t * apq;
                a[p][q] = 0.0;
                a[q][p] = 0.0;

                for r in 0..4 {
                    if r != p && r != q {
                        let arp = a[r][p];
                        let arq = a[r][q];
                        let new_arp = arp - s * (arq + tau * arp);
                        let new_arq = arq + s * (arp - tau * arq);
                        a[r][p] = new_arp;
                        a[p][r] = new_arp;
                        a[r][q] = new_arq;
                        a[q][r] = new_arq;
                    }
                }

                for row in &mut v {
                    let vrp = row[p];
                    let vrq = row[q];
                    row[p] = vrp - s * (vrq + tau * vrp);
                    row[q] = vrq + s * (vrp - tau * vrq);
                }
            }
        }
    }

    let mut max_idx = 0;
    let mut max_eigenval = a[0][0];
    for (i, row) in a.iter().enumerate().skip(1) {
        if row[i] > max_eigenval {
            max_eigenval = row[i];
            max_idx = i;
        }
    }

    let mut eigenvector = [v[0][max_idx], v[1][max_idx], v[2][max_idx], v[3][max_idx]];
    let norm = (eigenvector[0] * eigenvector[0]
        + eigenvector[1] * eigenvector[1]
        + eigenvector[2] * eigenvector[2]
        + eigenvector[3] * eigenvector[3])
        .sqrt();

    if norm < 1e-12 {
        return Err(ExtrinsicsError::DegenerateCorrespondences {
            reason: "Jacobi eigensolver failed to find non-zero eigenvector".to_string(),
        });
    }

    for x in &mut eigenvector {
        *x /= norm;
    }

    // Canonical sign convention: ensure w >= 0
    if eigenvector[0] < 0.0 {
        for x in &mut eigenvector {
            *x = -*x;
        }
    }

    Ok((max_eigenval, eigenvector))
}

/// State of the cross-camera extrinsics lifecycle manager.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExtrinsicsLifecycleState {
    /// No extrinsics certificate has been activated.
    Uncalibrated,
    /// An active, valid extrinsics certificate is installed.
    Active(Box<ExtrinsicsCertificate>, CameraIntrinsics),
    /// A previously active certificate has been invalidated due to contradiction or manual revocation.
    Invalidated {
        /// Digest of the invalidated certificate.
        certificate_digest: ContentDigest,
        /// Reason for invalidation.
        reason: String,
        /// Evidence correspondence that triggered the invalidation, if applicable.
        contradicting_evidence: Option<ExtrinsicsCorrespondence>,
    },
}

/// Manages the runtime lifecycle, verification, and invalidation of cross-camera extrinsics certificates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtrinsicsLifecycle {
    state: ExtrinsicsLifecycleState,
}

impl Default for ExtrinsicsLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

impl ExtrinsicsLifecycle {
    /// Creates a new uncalibrated lifecycle manager.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: ExtrinsicsLifecycleState::Uncalibrated,
        }
    }

    /// Returns the current lifecycle state.
    #[must_use]
    pub const fn state(&self) -> &ExtrinsicsLifecycleState {
        &self.state
    }

    /// Returns true if an active certificate is present.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self.state, ExtrinsicsLifecycleState::Active(_, _))
    }

    /// Activates a verified extrinsics certificate with target camera intrinsics certificate at the current time.
    pub fn activate_certificate(
        &mut self,
        certificate: ExtrinsicsCertificate,
        target_certificate: &IntrinsicsCertificate,
        now: TimestampNs,
    ) -> Result<(), ExtrinsicsError> {
        certificate.validate_at_time(now)?;
        target_certificate
            .validate_at_time(now)
            .map_err(ExtrinsicsError::IntrinsicsError)?;

        if certificate.target_intrinsics_digest != target_certificate.certificate_digest {
            return Err(ExtrinsicsError::TargetIntrinsicsDigestMismatch {
                expected: certificate.target_intrinsics_digest,
                actual: target_certificate.certificate_digest,
            });
        }

        self.state = ExtrinsicsLifecycleState::Active(
            Box::new(certificate),
            target_certificate.intrinsics.clone(),
        );
        Ok(())
    }

    /// Returns a reference to the active certificate, or fails if uncalibrated/invalidated.
    pub fn active_certificate(&self) -> Result<&ExtrinsicsCertificate, ExtrinsicsError> {
        match &self.state {
            ExtrinsicsLifecycleState::Active(cert, _) => Ok(cert.as_ref()),
            ExtrinsicsLifecycleState::Invalidated { reason, .. } => {
                Err(ExtrinsicsError::CertificateInvalidated {
                    reason: reason.clone(),
                })
            }
            ExtrinsicsLifecycleState::Uncalibrated => Err(ExtrinsicsError::InvalidTransform(
                "no active extrinsics certificate installed".to_string(),
            )),
        }
    }

    /// Returns a reference to the active certificate after verifying it is valid at `query_time`.
    pub fn active_certificate_at(
        &self,
        query_time: TimestampNs,
    ) -> Result<&ExtrinsicsCertificate, ExtrinsicsError> {
        let cert = self.active_certificate()?;
        cert.validate_at_time(query_time)?;
        Ok(cert)
    }

    /// Verifies a runtime cross-camera observation against the active certificate.
    ///
    /// If the observation contradicts the active certificate by exceeding `tolerance_upx`,
    /// this transitions the lifecycle to [`ExtrinsicsLifecycleState::Invalidated`]
    /// and returns [`ExtrinsicsError::ContradictedExtrinsics`].
    pub fn verify_observation(
        &mut self,
        corr: &ExtrinsicsCorrespondence,
        tolerance_upx: u64,
    ) -> Result<(), ExtrinsicsError> {
        let (cert, intrinsics) = match &self.state {
            ExtrinsicsLifecycleState::Active(c, intr) => (c.clone(), intr.clone()),
            ExtrinsicsLifecycleState::Invalidated { reason, .. } => {
                return Err(ExtrinsicsError::CertificateInvalidated {
                    reason: reason.clone(),
                });
            }
            ExtrinsicsLifecycleState::Uncalibrated => {
                return Err(ExtrinsicsError::InvalidTransform(
                    "cannot verify observation without active extrinsics certificate".to_string(),
                ));
            }
        };

        // Enforce observation capture timestamp is within certificate validity window
        cert.validate_at_time(corr.capture_time)?;

        if let Err(contradiction) = cert.verify_not_contradicted(corr, &intrinsics, tolerance_upx) {
            self.state = ExtrinsicsLifecycleState::Invalidated {
                certificate_digest: cert.certificate_digest,
                reason: format!("cross-camera reprojection contradiction: {contradiction}"),
                contradicting_evidence: Some(corr.clone()),
            };
            return Err(contradiction);
        }

        Ok(())
    }

    /// Explicitly invalidates the active extrinsics certificate.
    pub fn invalidate(
        &mut self,
        reason: String,
        contradicting_evidence: Option<ExtrinsicsCorrespondence>,
    ) {
        let digest = match &self.state {
            ExtrinsicsLifecycleState::Active(c, _) => c.certificate_digest,
            ExtrinsicsLifecycleState::Invalidated {
                certificate_digest, ..
            } => *certificate_digest,
            ExtrinsicsLifecycleState::Uncalibrated => ContentDigest::sha256(b"uncalibrated"),
        };
        self.state = ExtrinsicsLifecycleState::Invalidated {
            certificate_digest: digest,
            reason,
            contradicting_evidence,
        };
    }
}

/// Errors occurring in the cross-camera extrinsics solver and certificate subsystem.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExtrinsicsError {
    /// Insufficient correspondence points were provided.
    InsufficientCorrespondences {
        /// Number of correspondences provided.
        count: usize,
        /// Minimum required count.
        min_required: usize,
    },
    /// Too many correspondence points were provided, exceeding declared bound.
    TooManyCorrespondences {
        /// Actual count observed.
        actual: usize,
        /// Maximum allowed count.
        max: usize,
    },
    /// Correspondence points form a degenerate spatial configuration (e.g. collinear).
    DegenerateCorrespondences {
        /// Reason describing the degeneracy.
        reason: String,
    },
    /// Residual RMSE exceeds declared tolerance bound.
    ResidualExceedsTolerance {
        /// Observed RMSE in micro-pixels.
        actual_rmse_upx: u64,
        /// Maximum allowed RMSE in micro-pixels.
        max_allowed_upx: u64,
    },
    /// Extrinsics certificate requested outside its certified time validity interval.
    StaleCertificatePastValidity {
        /// Timestamp requested.
        requested: TimestampNs,
        /// Validity horizon upper bound.
        valid_until: TimestampNs,
    },
    /// Source camera device generation does not match certificate binding.
    SourceDeviceGenerationMismatch {
        /// Expected generation.
        expected: DeviceGeneration,
        /// Actual generation.
        actual: DeviceGeneration,
    },
    /// Target camera device generation does not match certificate binding.
    TargetDeviceGenerationMismatch {
        /// Expected generation.
        expected: DeviceGeneration,
        /// Actual generation.
        actual: DeviceGeneration,
    },
    /// Source camera firmware generation does not match certificate binding.
    SourceFirmwareGenerationMismatch {
        /// Expected generation.
        expected: FirmwareGeneration,
        /// Actual generation.
        actual: FirmwareGeneration,
    },
    /// Target camera firmware generation does not match certificate binding.
    TargetFirmwareGenerationMismatch {
        /// Expected generation.
        expected: FirmwareGeneration,
        /// Actual generation.
        actual: FirmwareGeneration,
    },
    /// Source intrinsics digest does not match certificate binding.
    SourceIntrinsicsDigestMismatch {
        /// Expected digest.
        expected: ContentDigest,
        /// Actual digest.
        actual: ContentDigest,
    },
    /// Target intrinsics digest does not match certificate binding.
    TargetIntrinsicsDigestMismatch {
        /// Expected digest.
        expected: ContentDigest,
        /// Actual digest.
        actual: ContentDigest,
    },
    /// Calibration generation does not match certificate binding.
    CalibrationGenerationMismatch {
        /// Expected generation.
        expected: CalibrationGeneration,
        /// Actual generation.
        actual: CalibrationGeneration,
    },
    /// Query camera device ID does not match certificate binding.
    CameraIdMismatch {
        /// Expected device ID.
        expected: DeviceId,
        /// Actual device ID observed.
        actual: DeviceId,
    },
    /// Source and target camera are identical (self-camera pair prohibited).
    IdenticalCameraPair {
        /// Camera device ID.
        camera: DeviceId,
    },
    /// Default identity transform is strictly prohibited for calibrated extrinsics.
    IdentityTransformProhibited,
    /// An observation contradicted the active certificate.
    ContradictedExtrinsics {
        /// Correspondence identifier that contradicted.
        correspondence_id: u64,
        /// Reprojection error observed in micro-pixels.
        observed_error_upx: u64,
        /// Maximum tolerance threshold in micro-pixels.
        tolerance_upx: u64,
    },
    /// Certificate has been invalidated and cannot be queried.
    CertificateInvalidated {
        /// Reason for invalidation.
        reason: String,
    },
    /// Certificate identifier cannot be empty.
    EmptyCertificateId,
    /// Certificate identifier byte length exceeds the declared bound.
    CertificateIdTooLong {
        /// Actual length observed.
        actual: usize,
        /// Maximum allowed length.
        max: usize,
    },
    /// Rotation matrix is non-orthogonal or reflection with determinant deviating from +1.
    NonOrthogonalRotation {
        /// Determinant in micro-units.
        det_upx: i64,
    },
    /// Rigid transform parameters are invalid.
    InvalidTransform(String),
    /// Intrinsics error encountered during reprojection or validation.
    IntrinsicsError(CalibrationError),
    /// Checked fixed-point arithmetic overflowed.
    ArithmeticOverflow,
    /// Contract encoding error.
    Contract(ContractError),
    /// Reference error.
    Reference(String),
}

impl fmt::Display for ExtrinsicsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsufficientCorrespondences {
                count,
                min_required,
            } => {
                write!(
                    f,
                    "insufficient cross-camera correspondences: {count} provided, minimum {min_required} required"
                )
            }
            Self::TooManyCorrespondences { actual, max } => {
                write!(
                    f,
                    "correspondence count {actual} exceeds maximum declared bound {max}"
                )
            }
            Self::DegenerateCorrespondences { reason } => {
                write!(f, "degenerate cross-camera correspondences: {reason}")
            }
            Self::ResidualExceedsTolerance {
                actual_rmse_upx,
                max_allowed_upx,
            } => {
                write!(
                    f,
                    "cross-camera reprojection RMSE {actual_rmse_upx} upx exceeds maximum tolerance {max_allowed_upx} upx"
                )
            }
            Self::StaleCertificatePastValidity {
                requested,
                valid_until,
            } => {
                write!(
                    f,
                    "extrinsics certificate expired: requested at {requested:?}, valid until {valid_until:?}"
                )
            }
            Self::SourceDeviceGenerationMismatch { expected, actual } => {
                write!(
                    f,
                    "source device generation mismatch: expected {expected}, actual {actual}"
                )
            }
            Self::TargetDeviceGenerationMismatch { expected, actual } => {
                write!(
                    f,
                    "target device generation mismatch: expected {expected}, actual {actual}"
                )
            }
            Self::SourceFirmwareGenerationMismatch { expected, actual } => {
                write!(
                    f,
                    "source firmware generation mismatch: expected {expected}, actual {actual}"
                )
            }
            Self::TargetFirmwareGenerationMismatch { expected, actual } => {
                write!(
                    f,
                    "target firmware generation mismatch: expected {expected}, actual {actual}"
                )
            }
            Self::SourceIntrinsicsDigestMismatch { expected, actual } => {
                write!(
                    f,
                    "source intrinsics digest mismatch: expected {expected}, actual {actual}"
                )
            }
            Self::TargetIntrinsicsDigestMismatch { expected, actual } => {
                write!(
                    f,
                    "target intrinsics digest mismatch: expected {expected}, actual {actual}"
                )
            }
            Self::CalibrationGenerationMismatch { expected, actual } => {
                write!(
                    f,
                    "calibration generation mismatch: expected {expected}, actual {actual}"
                )
            }
            Self::CameraIdMismatch { expected, actual } => {
                write!(
                    f,
                    "camera device ID mismatch: expected {expected}, actual {actual}"
                )
            }
            Self::IdenticalCameraPair { camera } => {
                write!(
                    f,
                    "cross-camera extrinsics cannot bind camera to itself: {camera}"
                )
            }
            Self::IdentityTransformProhibited => {
                write!(f, "default identity transform is strictly prohibited")
            }
            Self::ContradictedExtrinsics {
                correspondence_id,
                observed_error_upx,
                tolerance_upx,
            } => {
                write!(
                    f,
                    "extrinsics contradicted by correspondence {correspondence_id}: error {observed_error_upx} upx exceeds tolerance {tolerance_upx} upx"
                )
            }
            Self::CertificateInvalidated { reason } => {
                write!(f, "extrinsics certificate is invalidated: {reason}")
            }
            Self::EmptyCertificateId => {
                write!(f, "certificate identifier cannot be empty")
            }
            Self::CertificateIdTooLong { actual, max } => {
                write!(
                    f,
                    "certificate identifier length {actual} exceeds maximum declared bound {max}"
                )
            }
            Self::NonOrthogonalRotation { det_upx } => {
                write!(
                    f,
                    "rotation matrix is non-orthogonal (determinant: {det_upx} micro-units)"
                )
            }
            Self::InvalidTransform(reason) => {
                write!(f, "invalid rigid transform: {reason}")
            }
            Self::IntrinsicsError(err) => {
                write!(f, "intrinsics error: {err}")
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

impl std::error::Error for ExtrinsicsError {}

impl From<CalibrationError> for ExtrinsicsError {
    fn from(err: CalibrationError) -> Self {
        Self::IntrinsicsError(err)
    }
}

impl From<ContractError> for ExtrinsicsError {
    fn from(err: ContractError) -> Self {
        Self::Contract(err)
    }
}

impl From<ReferenceError> for ExtrinsicsError {
    fn from(err: ReferenceError) -> Self {
        Self::Reference(format!("{err:?}"))
    }
}

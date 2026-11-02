#![forbid(unsafe_code)]
//! Geometry projection of an already authenticated calibration owner.

use std::collections::BTreeSet;

use fss_reference::ingest::scene_calibration::{
    RetainedSceneCalibration, SceneCalibrationImageProfile,
};

use super::{SceneRig, SceneRigCamera, SceneRigError};
use fss_core::{CanonicalEncoder, ContentDigest};
use fss_geometry::{GeometryBasis, WorkBudget};
use fss_twin::{PropertyTwin, TrackingCamera};

/// Semantic identity of a camera rig resolved from exact retained calibration authority.
pub const ADOPTED_SCENE_RIG_DOMAIN: &str = "fss.scene_camera_rig_adopted.v1";
/// Semantic identity of an adopted virtual pinhole rig requiring native image preparation.
pub const ADOPTED_RECTIFIED_SCENE_RIG_DOMAIN: &str = "fss.scene_camera_rig_adopted_rectified.v1";

/// Owner declarations that a calibration does not measure or authorize.
///
/// Camera geometry and generation come exclusively from the sealed calibration
/// owner. These declarations give scene-local image/clock/privacy handles and a
/// requested use interval; they do not establish physical currency or clock accuracy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdoptedSceneCameraBinding {
    /// Original calibrated camera handle, never an alias for another camera.
    pub camera: u64,
    /// Explicit source-scene object mapping.
    pub source_object_id: String,
    /// Scene-local image-mode handle. Original-pinhole admission binds the original domain;
    /// rectification admission binds the virtual target grid. The actual source/output domain
    /// digests remain explicit in the native source-to-feature image receipt.
    pub image_domain: u64,
    /// Declared common capture clock.
    pub clock: u64,
    /// Declared privacy domain; grants no source access authority.
    pub privacy_domain: u64,
    /// Declared use interval in the common clock, inclusive.
    pub validity: [u64; 2],
}

impl SceneRig {
    /// Project an authenticated, adopted calibration into existing native scene geometry.
    ///
    /// The caller must bind every actual selected source to the owner's sensor and
    /// original image domain, and revalidate the owner after source-dependent analysis.
    /// A returned rig is immutable geometry, not a lease on calibration authority.
    /// Local adjustment covariance is deliberately not converted into a conservative
    /// projection bound: every camera retains unknown absolute calibration error.
    pub fn from_retained_calibration(
        twin: &PropertyTwin,
        calibration: &RetainedSceneCalibration,
        geometry_basis: (u64, u64),
        declarations: &[AdoptedSceneCameraBinding],
        work: &mut WorkBudget<'_>,
    ) -> Result<Self, SceneRigError> {
        Self::from_calibration_profile(
            twin,
            calibration,
            geometry_basis,
            declarations,
            work,
            SceneCalibrationImageProfile::OriginalPinhole,
        )
    }

    /// Project explicitly resolved radial camera models into their fixed virtual pinhole grids.
    ///
    /// The target intrinsics and dimensions are exactly each refined original camera matrix.
    /// No numeric target override is accepted. The owner must compare every source declaration
    /// to `calibration.rectification_spec`, compile the native plans before decoding, bind each
    /// actual output domain/receipt, and revalidate adoption after analysis. Calling this method
    /// alone does not rectify a source, authorize raw pixels as pinhole, or grant an authority
    /// lease. Mixed zero-radial/direct and native-rectified views require explicit owner checks.
    pub fn from_retained_rectified_calibration(
        twin: &PropertyTwin,
        calibration: &RetainedSceneCalibration,
        geometry_basis: (u64, u64),
        declarations: &[AdoptedSceneCameraBinding],
        work: &mut WorkBudget<'_>,
    ) -> Result<Self, SceneRigError> {
        Self::from_calibration_profile(
            twin,
            calibration,
            geometry_basis,
            declarations,
            work,
            SceneCalibrationImageProfile::NativeRadialRectification,
        )
    }

    fn from_calibration_profile(
        twin: &PropertyTwin,
        calibration: &RetainedSceneCalibration,
        geometry_basis: (u64, u64),
        declarations: &[AdoptedSceneCameraBinding],
        work: &mut WorkBudget<'_>,
        image_profile: SceneCalibrationImageProfile,
    ) -> Result<Self, SceneRigError> {
        work.charge(0)?;
        if calibration.image_profile() != image_profile
            || (image_profile == SceneCalibrationImageProfile::OriginalPinhole
                && calibration
                    .cameras()
                    .iter()
                    .any(|camera| camera.record().distortion != [0.0, 0.0]))
        {
            return Err(SceneRigError::Unsupported);
        }
        if calibration.twin_package().bytes() != twin.digest()
            || calibration.twin_source().bytes() != twin.source_scene_digest()
            || GeometryBasis::new(geometry_basis.0, geometry_basis.1)? != twin.basis()
        {
            return Err(SceneRigError::Basis);
        }
        if declarations.is_empty()
            || declarations.len() > 16
            || declarations.len() != calibration.cameras().len()
        {
            return Err(SceneRigError::Limit);
        }
        work.charge(8192 + 8192 * declarations.len() as u64)?;
        let mut handles = BTreeSet::new();
        let mut objects = BTreeSet::new();
        let mut cameras = Vec::with_capacity(declarations.len());
        for declaration in declarations {
            work.charge(0)?;
            if declaration.camera == 0
                || declaration.image_domain == 0
                || declaration.clock == 0
                || declaration.privacy_domain == 0
                || declaration.validity[0] > declaration.validity[1]
            {
                return Err(SceneRigError::Numeric);
            }
            let label = &declaration.source_object_id;
            if label.is_empty() || label.len() > 256 {
                return Err(SceneRigError::Limit);
            }
            if label.trim() != label || label.chars().any(char::is_control) {
                return Err(SceneRigError::Format);
            }
            if !handles.insert(declaration.camera) || !objects.insert(label.clone()) {
                return Err(SceneRigError::Duplicate);
            }
            let owner = calibration
                .camera(declaration.camera)
                .ok_or(SceneRigError::Basis)?;
            cameras.push(SceneRigCamera {
                source_object_id: label.clone(),
                privacy_domain: declaration.privacy_domain,
                camera: TrackingCamera {
                    geometry: twin.basis(),
                    camera: owner.record().identity.camera,
                    // This handle denotes the retained per-camera adoption. The
                    // semantic rig also binds its full receipt and both generations.
                    calibration: owner.adoption().receipt.adoption,
                    image_domain: declaration.image_domain,
                    clock: declaration.clock,
                    validity: declaration.validity,
                    pose: owner.pose(),
                    intrinsics: owner.intrinsics(),
                    error: None,
                },
            });
        }
        cameras.sort_by_key(|row| row.camera.camera);
        let mut encoder = CanonicalEncoder::new();
        encoder.text(match image_profile {
            SceneCalibrationImageProfile::OriginalPinhole => ADOPTED_SCENE_RIG_DOMAIN,
            SceneCalibrationImageProfile::NativeRadialRectification => {
                ADOPTED_RECTIFIED_SCENE_RIG_DOMAIN
            }
        });
        encoder.digest(calibration.digest());
        encoder.digest(calibration.calibration_identity());
        encoder.digest(calibration.calibration_file_digest());
        encoder.digest(calibration.twin_package());
        encoder.digest(calibration.twin_source());
        encoder.u64(geometry_basis.0);
        encoder.u64(geometry_basis.1);
        encoder.text("RH_Z_UP");
        encoder.text(twin.evaluation_scope());
        encoder.u64(cameras.len() as u64);
        for row in &cameras {
            let camera = row.camera;
            encoder.text(&row.source_object_id);
            for value in [
                camera.camera,
                camera.calibration,
                camera.image_domain,
                camera.clock,
                row.privacy_domain,
                camera.validity[0],
                camera.validity[1],
            ] {
                encoder.u64(value);
            }
            encoder.text("undistorted_pinhole");
            encoder.text("adopted_current");
            encoder.bool(false);
            for value in camera
                .pose
                .rotation()
                .into_iter()
                .flatten()
                .chain(camera.pose.translation())
            {
                encoder.u64(if value == 0.0 { 0 } else { value.to_bits() });
            }
            for value in camera.intrinsics.dimensions() {
                encoder.u32(value);
            }
            for value in camera
                .intrinsics
                .focal_lengths()
                .into_iter()
                .chain(camera.intrinsics.principal_point())
            {
                encoder.u64(if value == 0.0 { 0 } else { value.to_bits() });
            }
        }
        let encoded = encoder.finish_checked().map_err(|_| SceneRigError::Limit)?;
        let digest = ContentDigest::sha256(&encoded);
        work.charge(0)?;
        Ok(Self {
            cameras,
            digest,
            source_scene_digest: calibration.twin_source(),
            twin_digest: calibration.twin_package(),
            geometry_basis,
            evaluation_scope: twin.evaluation_scope().to_owned(),
        })
    }
}

#[cfg(test)]
#[path = "adopted_rectification_tests.rs"]
mod rectification_tests;

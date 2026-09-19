#![forbid(unsafe_code)]
//! Immutable camera-registration candidates from uniquely held-out-validated focal scans.
//! Geometry can be bound to owner-resolved tracking handles, but never activates authority itself.

use fss_geometry::{FocalSampleOutcome,FocalValidationSet,PinholeIntrinsics,PlanarSupport,
    PoseValidation,RigidPose};
use crate::{PropertyTwin,TrackingCamera};
use crate::calibration_monitor::FrozenCalibration;
use crate::focal_localization::{FocalLocalization,FocalLocalizationOutcome};
use crate::localization::{ImageIdentity,LocalizationAtlas,LocalizationCamera};

/// Reasons a uniquely held-out-validated registration candidate cannot be derived or bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrationCandidateError {
    /// Twin, atlas, and localization digests do not share one basis.
    BasisMismatch,
    /// The localization outcome carries no focal-pose scan.
    NoScan,
    /// The validation set does not belong to the localization's focal scan.
    ValidationMismatch,
    /// Held-out validation does not select exactly one focal-pose mode.
    NotUnique,
    /// The validated sample or candidate index is out of range.
    InvalidIndex,
    /// A supplied owner binding (camera, calibration, clock, or digest) is invalid.
    InvalidBinding,
}
impl std::fmt::Display for RegistrationCandidateError {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{
        f.write_str(match self{
            Self::BasisMismatch=>"registration candidate basis mismatch",
            Self::NoScan=>"registration has no focal-pose scan",
            Self::ValidationMismatch=>"validation does not belong to this focal scan",
            Self::NotUnique=>"held-out validation does not select exactly one focal-pose mode",
            Self::InvalidIndex=>"validated focal-pose index is invalid",
            Self::InvalidBinding=>"invalid owner tracking/calibration binding",
        })
    }
}
impl std::error::Error for RegistrationCandidateError{}

/// Owner-resolved process-local handles supplied by the caller when binding validated
/// geometry into a [`TrackingCamera`]. All identity fields are chosen by the owner; the
/// solver never invents them.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TrackingCameraBinding {
    /// Non-zero process-local camera identity.
    pub camera:u64,
    /// Non-zero process-local calibration identity.
    pub calibration:u64,
    /// Non-zero process-local image-domain identity.
    pub image_domain:u64,
    /// Digest that must equal the registration query's image-domain digest.
    pub image_domain_digest:[u8;32],
    /// Non-zero process-local clock identity (logical clock stamp).
    pub clock:u64,
    /// Half-open `[start,end)` nanosecond validity window; `start <= end`.
    pub validity:[u64;2],
    /// Optional projection-error model; if present it must be valid for the registration intrinsics.
    pub error:Option<crate::ProjectionError>,
}

/// A focal-pose registration candidate uniquely selected by held-out validation.
/// Immutable: it records the digests it was derived from and the fit/holdout statistics
/// of exactly one passing candidate.
#[derive(Clone, Debug)]
pub struct ValidatedCameraRegistration {
    /// Property-twin basis digest the registration was derived against.
    pub twin_digest:[u8;32],
    /// Localization-atlas digest the registration was derived against.
    pub atlas_digest:[u8;32],
    /// Image identity (domain, geometry) of the queried frame.
    pub query:ImageIdentity,
    /// Index of the passing sample within the focal scan.
    pub sample:usize,
    /// Index of the passing candidate within the sample's search.
    pub candidate:usize,
    /// Pinhole intrinsics estimated for this candidate.
    pub intrinsics:PinholeIntrinsics,
    /// Camera pose for this candidate in twin-basis coordinates.
    pub pose:RigidPose,
    /// Optional planar support detected during the candidate search.
    pub planar_support:Option<PlanarSupport>,
    /// Inlier landmark ids used for the fit.
    pub fit_landmarks:Vec<u64>,
    /// Root-mean-square reprojection error over fit landmarks, in pixels.
    pub fit_rms_px:f64,
    /// Maximum reprojection error over fit landmarks, in pixels.
    pub fit_maximum_error_px:f64,
    /// Held-out validation report that uniquely selected this candidate.
    pub holdout:PoseValidation,
}
impl ValidatedCameraRegistration {
    /// Construct the digest-oriented frozen calibration consumed by the live monitor.
    /// The caller supplies the immutable calibration identity; zero is refused.
    pub fn frozen_calibration(&self,id:[u8;32])->Result<FrozenCalibration,RegistrationCandidateError>{
        if id==[0;32]{return Err(RegistrationCandidateError::InvalidBinding);}
        Ok(FrozenCalibration{id,camera:LocalizationCamera{intrinsics:self.intrinsics,
            image_domain:self.query.image_domain},pose:self.pose})
    }

    /// Bind validated geometry to owner-resolved process-local handles. This returns a
    /// snapshot suitable for existing tracking code; policy/authority owners still decide
    /// whether that snapshot becomes active. The solver cannot invent camera, clock, or
    /// generation identities.
    pub fn bind_tracking_camera(&self,twin:&PropertyTwin,binding:TrackingCameraBinding)
        ->Result<TrackingCamera,RegistrationCandidateError>{
        if twin.digest()!=self.twin_digest || binding.image_domain_digest!=self.query.image_domain
            || binding.camera==0 || binding.calibration==0 || binding.image_domain==0 || binding.clock==0
            || binding.validity[0]>binding.validity[1]
            || binding.error.is_some_and(|e|!e.valid_for(self.intrinsics)){
            return Err(RegistrationCandidateError::InvalidBinding);
        }
        Ok(TrackingCamera{geometry:twin.basis(),camera:binding.camera,calibration:binding.calibration,
            image_domain:binding.image_domain,clock:binding.clock,validity:binding.validity,
            pose:self.pose,intrinsics:self.intrinsics,error:binding.error})
    }
}

/// Select the unique held-out-validated focal-pose registration candidate for a twin/atlas pair.
/// Returns [`RegistrationCandidateError::NotUnique`] unless validation passes for exactly one mode.
pub fn select_unique_focal_registration(twin:&PropertyTwin,atlas:&LocalizationAtlas,
    localization:&FocalLocalization,validation:&FocalValidationSet<'_>)
    ->Result<ValidatedCameraRegistration,RegistrationCandidateError>{
    if atlas.twin_digest()!=twin.digest() || localization.matches.atlas!=atlas.digest(){return Err(RegistrationCandidateError::BasisMismatch);}
    let FocalLocalizationOutcome::Scan(scan)=&localization.outcome else{return Err(RegistrationCandidateError::NoScan);};
    if !std::ptr::eq(scan,validation.scan()){return Err(RegistrationCandidateError::ValidationMismatch);}
    let (si,ci)=validation.unique_passing_candidate().ok_or(RegistrationCandidateError::NotUnique)?;
    let sample=scan.samples().get(si).ok_or(RegistrationCandidateError::InvalidIndex)?;
    let FocalSampleOutcome::Candidates(search)=sample.outcome() else{return Err(RegistrationCandidateError::InvalidIndex);};
    let candidate=search.candidates().get(ci).ok_or(RegistrationCandidateError::InvalidIndex)?;
    let report=validation.reports().iter().find(|r|r.sample==si&&r.candidate==ci).ok_or(RegistrationCandidateError::ValidationMismatch)?;
    if !report.validation.passed{return Err(RegistrationCandidateError::ValidationMismatch);}
    Ok(ValidatedCameraRegistration{twin_digest:twin.digest(),atlas_digest:atlas.digest(),query:localization.matches.query,
        sample:si,candidate:ci,intrinsics:sample.intrinsics(),pose:candidate.pose(),planar_support:search.planar_support(),
        fit_landmarks:candidate.inlier_landmarks().to_vec(),fit_rms_px:candidate.rms_px(),
        fit_maximum_error_px:candidate.maximum_error_px(),holdout:report.validation.clone()})
}

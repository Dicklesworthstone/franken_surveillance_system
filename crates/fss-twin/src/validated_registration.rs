#![forbid(unsafe_code)]
//! Immutable camera-registration candidates from uniquely held-out-validated focal scans.
//! Geometry can be bound to owner-resolved tracking handles, but never activates authority itself.

use fss_geometry::{FocalSampleOutcome,FocalValidationSet,PinholeIntrinsics,PlanarSupport,
    PoseValidation,RigidPose};
use crate::{PropertyTwin,TrackingCamera};
use crate::calibration_monitor::FrozenCalibration;
use crate::focal_localization::{FocalLocalization,FocalLocalizationOutcome};
use crate::localization::{ImageIdentity,LocalizationAtlas,LocalizationCamera};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrationCandidateError {
    BasisMismatch, NoScan, ValidationMismatch, NotUnique, InvalidIndex, InvalidBinding,
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

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TrackingCameraBinding {
    pub camera:u64,
    pub calibration:u64,
    pub image_domain:u64,
    pub image_domain_digest:[u8;32],
    pub clock:u64,
    pub validity:[u64;2],
    pub error:Option<f64>,
}

#[derive(Clone, Debug)]
pub struct ValidatedCameraRegistration {
    pub twin_digest:[u8;32], pub atlas_digest:[u8;32], pub query:ImageIdentity,
    pub sample:usize, pub candidate:usize, pub intrinsics:PinholeIntrinsics,
    pub pose:RigidPose, pub planar_support:Option<PlanarSupport>, pub fit_landmarks:Vec<u64>,
    pub fit_rms_px:f64, pub fit_maximum_error_px:f64, pub holdout:PoseValidation,
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
            || binding.error.is_some_and(|e|!e.is_finite() || e<0.0 || e>1e9){
            return Err(RegistrationCandidateError::InvalidBinding);
        }
        Ok(TrackingCamera{geometry:twin.basis(),camera:binding.camera,calibration:binding.calibration,
            image_domain:binding.image_domain,clock:binding.clock,validity:binding.validity,
            pose:self.pose,intrinsics:self.intrinsics,error:binding.error})
    }
}

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

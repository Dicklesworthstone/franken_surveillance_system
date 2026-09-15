#![forbid(unsafe_code)]
//! Source-linked registration candidate for a uniquely held-out-validated focal+k1 mode.
//! It can compile the exact native rectification generation needed by downstream pinhole code,
//! but activation and process-local handles remain owner-controlled.

use fss_geometry::{PoseValidation,RigidPose,PinholeIntrinsics,WorkBudget};
use crate::{PropertyTwin,TrackingCamera};
use crate::calibration_monitor::FrozenCalibration;
use crate::localization::{ImageIdentity,LocalizationAtlas,LocalizationCamera};
use crate::radial_localization::{RadialLocalization,RadialLocalizationOutcome,RadialSampleOutcome,RadialValidationSet};
use crate::rectification::{LensDistortion,LumaRange,RectificationError,RectificationPlan,RectificationSpec};
use crate::validated_registration::TrackingCameraBinding;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RadialRegistrationError {
    BasisMismatch,NoScan,ValidationMismatch,NotUnique,InvalidIndex,InvalidBinding,Rectification(RectificationError),
}
impl From<RectificationError> for RadialRegistrationError{fn from(v:RectificationError)->Self{Self::Rectification(v)}}
impl std::fmt::Display for RadialRegistrationError{
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{f.write_str(match self{
        Self::BasisMismatch=>"radial registration basis mismatch",Self::NoScan=>"radial registration has no lens scan",
        Self::ValidationMismatch=>"radial validation does not belong to this scan",Self::NotUnique=>"held-out validation does not select exactly one lens-pose mode",
        Self::InvalidIndex=>"validated lens-pose index invalid",Self::InvalidBinding=>"invalid radial calibration owner binding",
        Self::Rectification(_)=>"validated radial registration could not compile rectification",
    })}
}
impl std::error::Error for RadialRegistrationError{}

#[derive(Clone, Debug)]
pub struct ValidatedRadialCameraRegistration {
    pub twin_digest:[u8;32],pub atlas_digest:[u8;32],pub raw_query:ImageIdentity,
    pub sample:usize,pub candidate:usize,pub raw_intrinsics:PinholeIntrinsics,pub k1:f64,
    pub maximum_undistorted_radius:f64,pub pose:RigidPose,pub fit_landmarks:Vec<u64>,
    pub fit_rms_px:f64,pub fit_maximum_error_px:f64,pub holdout:PoseValidation,
}
impl ValidatedRadialCameraRegistration {
    pub fn rectification_spec(&self,calibration:[u8;32],range:LumaRange)->Result<RectificationSpec,RadialRegistrationError>{
        if calibration==[0;32]{return Err(RadialRegistrationError::InvalidBinding);}
        Ok(RectificationSpec{source:self.raw_intrinsics,target:self.raw_intrinsics,
            distortion:LensDistortion::BrownConrady{radial:[self.k1,0.0,0.0],tangential:[0.0,0.0]},
            maximum_radius:self.maximum_undistorted_radius,source_domain:self.raw_query.image_domain,calibration,range})
    }
    pub fn compile_rectification(&self,calibration:[u8;32],range:LumaRange,budget:&mut WorkBudget<'_>)
        ->Result<RectificationPlan,RadialRegistrationError>{
        Ok(RectificationPlan::compile(self.rectification_spec(calibration,range)?,budget)?)
    }
    pub fn bind_tracking_camera(&self,twin:&PropertyTwin,plan:&RectificationPlan,binding:TrackingCameraBinding)
        ->Result<TrackingCamera,RadialRegistrationError>{
        let spec=plan.spec();
        let expected=LensDistortion::BrownConrady{radial:[self.k1,0.0,0.0],tangential:[0.0,0.0]};
        if twin.digest()!=self.twin_digest || spec.source!=self.raw_intrinsics || spec.target!=self.raw_intrinsics
            || spec.source_domain!=self.raw_query.image_domain || spec.distortion!=expected
            || (spec.maximum_radius-self.maximum_undistorted_radius).abs()>1e-12
            || binding.image_domain_digest!=plan.output_domain() || binding.camera==0||binding.calibration==0
            || binding.image_domain==0||binding.clock==0||binding.validity[0]>binding.validity[1]
            || binding.error.is_some_and(|e|!e.is_finite()||e<0.0||e>1e9){return Err(RadialRegistrationError::InvalidBinding);}
        Ok(TrackingCamera{geometry:twin.basis(),camera:binding.camera,calibration:binding.calibration,
            image_domain:binding.image_domain,clock:binding.clock,validity:binding.validity,pose:self.pose,
            intrinsics:self.raw_intrinsics,error:binding.error})
    }
    pub fn frozen_calibration(&self,plan:&RectificationPlan,id:[u8;32])->Result<FrozenCalibration,RadialRegistrationError>{
        if id==[0;32] || plan.spec().source_domain!=self.raw_query.image_domain || plan.spec().target!=self.raw_intrinsics{
            return Err(RadialRegistrationError::InvalidBinding);
        }
        Ok(FrozenCalibration{id,camera:LocalizationCamera{intrinsics:self.raw_intrinsics,image_domain:plan.output_domain()},pose:self.pose})
    }
}

pub fn select_unique_radial_registration(twin:&PropertyTwin,atlas:&LocalizationAtlas,
    localization:&RadialLocalization,validation:&RadialValidationSet<'_>)
    ->Result<ValidatedRadialCameraRegistration,RadialRegistrationError>{
    if atlas.twin_digest()!=twin.digest()||localization.matches.atlas!=atlas.digest(){return Err(RadialRegistrationError::BasisMismatch);}
    let RadialLocalizationOutcome::Scan(scan)=&localization.outcome else{return Err(RadialRegistrationError::NoScan);};
    if !std::ptr::eq(scan,validation.scan()){return Err(RadialRegistrationError::ValidationMismatch);}
    let (si,ci)=validation.unique_passing_candidate().ok_or(RadialRegistrationError::NotUnique)?;
    let sample=scan.samples.get(si).ok_or(RadialRegistrationError::InvalidIndex)?;
    let RadialSampleOutcome::Candidates(search)=&sample.outcome else{return Err(RadialRegistrationError::InvalidIndex);};
    let candidate=search.candidates().get(ci).ok_or(RadialRegistrationError::InvalidIndex)?;
    let report=validation.reports().iter().find(|r|r.sample==si&&r.candidate==ci).ok_or(RadialRegistrationError::ValidationMismatch)?;
    if !report.validation.passed{return Err(RadialRegistrationError::ValidationMismatch);}
    Ok(ValidatedRadialCameraRegistration{twin_digest:twin.digest(),atlas_digest:atlas.digest(),raw_query:localization.matches.query,
        sample:si,candidate:ci,raw_intrinsics:sample.intrinsics,k1:sample.k1,maximum_undistorted_radius:scan.options.maximum_undistorted_radius,
        pose:candidate.pose(),fit_landmarks:candidate.inlier_landmarks().to_vec(),fit_rms_px:candidate.rms_px(),
        fit_maximum_error_px:candidate.maximum_error_px(),holdout:report.validation.clone()})
}

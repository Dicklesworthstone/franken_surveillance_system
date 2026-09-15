#![forbid(unsafe_code)]
//! Immutable camera-registration candidates from uniquely held-out-validated focal scans.
//! This module prepares evidence-linked geometry; it never activates calibration authority.

use fss_geometry::{FocalSampleOutcome,FocalValidationSet,PinholeIntrinsics,PlanarSupport,
    PoseValidation,RigidPose};
use crate::PropertyTwin;
use crate::focal_localization::{FocalLocalization,FocalLocalizationOutcome};
use crate::localization::{ImageIdentity,LocalizationAtlas};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrationCandidateError {
    BasisMismatch,
    NoScan,
    ValidationMismatch,
    NotUnique,
    InvalidIndex,
}
impl std::fmt::Display for RegistrationCandidateError {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{
        f.write_str(match self{
            Self::BasisMismatch=>"registration candidate basis mismatch",
            Self::NoScan=>"registration has no focal-pose scan",
            Self::ValidationMismatch=>"validation does not belong to this focal scan",
            Self::NotUnique=>"held-out validation does not select exactly one focal-pose mode",
            Self::InvalidIndex=>"validated focal-pose index is invalid",
        })
    }
}
impl std::error::Error for RegistrationCandidateError{}

/// Evidence-linked geometry ready for owner review/activation by a separate calibration owner.
/// No field grants device identity, physical accuracy, persistence, or tracking authority.
#[derive(Clone, Debug)]
pub struct ValidatedCameraRegistration {
    pub twin_digest:[u8;32],
    pub atlas_digest:[u8;32],
    pub query:ImageIdentity,
    pub sample:usize,
    pub candidate:usize,
    pub intrinsics:PinholeIntrinsics,
    pub pose:RigidPose,
    pub planar_support:Option<PlanarSupport>,
    pub fit_landmarks:Vec<u64>,
    pub fit_rms_px:f64,
    pub fit_maximum_error_px:f64,
    pub holdout:PoseValidation,
}

/// Select only a unique held-out passing mode from the exact scan embedded in this
/// localization result. Pointer identity prevents rebinding a validation from an
/// otherwise similar scan generated from different correspondences.
pub fn select_unique_focal_registration(twin:&PropertyTwin,atlas:&LocalizationAtlas,
    localization:&FocalLocalization,validation:&FocalValidationSet<'_>)
    ->Result<ValidatedCameraRegistration,RegistrationCandidateError>{
    if atlas.twin_digest()!=twin.digest() || localization.matches.atlas!=atlas.digest(){
        return Err(RegistrationCandidateError::BasisMismatch);
    }
    let FocalLocalizationOutcome::Scan(scan)=&localization.outcome else{
        return Err(RegistrationCandidateError::NoScan);
    };
    if !std::ptr::eq(scan,validation.scan()){
        return Err(RegistrationCandidateError::ValidationMismatch);
    }
    let (sample_index,candidate_index)=validation.unique_passing_candidate()
        .ok_or(RegistrationCandidateError::NotUnique)?;
    let sample=scan.samples().get(sample_index).ok_or(RegistrationCandidateError::InvalidIndex)?;
    let FocalSampleOutcome::Candidates(search)=sample.outcome() else{
        return Err(RegistrationCandidateError::InvalidIndex);
    };
    let candidate=search.candidates().get(candidate_index).ok_or(RegistrationCandidateError::InvalidIndex)?;
    let report=validation.reports().iter().find(|r|r.sample==sample_index && r.candidate==candidate_index)
        .ok_or(RegistrationCandidateError::ValidationMismatch)?;
    if !report.validation.passed{return Err(RegistrationCandidateError::ValidationMismatch);}
    Ok(ValidatedCameraRegistration{
        twin_digest:twin.digest(),atlas_digest:atlas.digest(),query:localization.matches.query,
        sample:sample_index,candidate:candidate_index,intrinsics:sample.intrinsics(),pose:candidate.pose(),
        planar_support:search.planar_support(),fit_landmarks:candidate.inlier_landmarks().to_vec(),
        fit_rms_px:candidate.rms_px(),fit_maximum_error_px:candidate.maximum_error_px(),
        holdout:report.validation.clone(),
    })
}

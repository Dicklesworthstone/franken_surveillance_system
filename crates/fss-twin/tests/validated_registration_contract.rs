#![forbid(unsafe_code)]
mod common;

use std::error::Error;
use fss_geometry::{Correspondence,FocalScanOptions,PoseSolverOptions,WorkBudget};
use fss_twin::focal_localization::*;
use fss_twin::localization::*;
use fss_twin::validated_registration::*;

type Test=Result<(),Box<dyn Error>>;
fn descriptor(id:u64)->BinaryDescriptor{BinaryDescriptor([id.wrapping_mul(0x9e3779b97f4a7c15),!id,id.rotate_left(17),id.wrapping_mul(0xd6e8feb86659fd93)])}
fn world(id:u64)->[f64;3]{let n=id as f64;[2.0*(n*0.7).sin(),1.5*(n*1.3).cos(),1.2*(n*0.31).sin()]}
fn pixel(w:[f64;3])->[f64;2]{let x=0.8*w[0]+0.6*w[2]+0.3;let y=w[1]-0.4;let z=-0.6*w[0]+0.8*w[2]+8.0;[800.0*x/z+960.0,820.0*y/z+540.0]}
fn frame(exposure:u8,query:bool,budget:&mut WorkBudget<'_>)->Result<FeatureFrame,LocalizationError>{
    let features=(1..=32).map(|id|ImageFeature{id,pixel:if query{pixel(world(id))}else{[40.0+id as f64*20.0,100.0+(id%8) as f64*40.0]},descriptor:descriptor(id)}).collect();
    FeatureFrame::new(ImageIdentity{exposure:[exposure;32],pixels:[exposure.wrapping_add(20);32],image_domain:[3;32],dimensions:[1920,1080]},[9;32],features,budget)
}
fn atlas(twin:&fss_twin::PropertyTwin,budget:&mut WorkBudget<'_>)->Result<LocalizationAtlas,Box<dyn Error>>{
    let reference=frame(1,false,budget)?;
    let landmarks=(1..=32).map(|id|AtlasLandmark{id,physical_group:id,feature:0,world:world(id),evidence:[7;32],error:None}).collect();
    let bindings=(1..=32).map(|id|AtlasBinding{landmark:id,reference:1,image_feature:id}).collect();
    Ok(LocalizationAtlas::new(twin,landmarks,vec![AtlasReference{id:1,frame:reference}],bindings,budget)?)
}
fn scan()->FocalScanOptions{FocalScanOptions{minimum_fx_px:400.0,maximum_fx_px:1600.0,y_over_x:820.0/800.0,principal_point:[960.0,540.0],samples:33,pose:PoseSolverOptions{ransac_trials:0,..PoseSolverOptions::default()}}}
fn holdout()->Vec<Correspondence>{(101..=112).map(|id|Correspondence{landmark:id,physical_group:id,world:world(id),pixel:pixel(world(id))}).collect()}

#[test]
fn only_unique_held_out_mode_becomes_registration_candidate_and_owner_bound_snapshot()->Test{
    let twin=common::twin(&[0.0],None)?;let mut budget=WorkBudget::new(1_500_000_000);let atlas=atlas(&twin,&mut budget)?;
    let query=frame(2,true,&mut budget)?;
    let localization=localize_focal_scan(&atlas,&twin,&query,[3;32],MatchOptions{maximum_distance:0,ratio_percent:80},scan(),&mut budget)?;
    let FocalLocalizationOutcome::Scan(focal)=&localization.outcome else{return Err("no scan".into());};
    let validation=focal.validate_all_candidates(twin.basis(),&holdout(),0.01,&mut budget)?;
    assert_eq!(validation.unique_passing_candidate(),Some((16,0)));
    let candidate=select_unique_focal_registration(&twin,&atlas,&localization,&validation)?;
    assert!((candidate.intrinsics.focal_lengths()[0]-800.0).abs()<1e-9);
    assert_eq!(candidate.query.exposure,[2;32]);assert_eq!(candidate.fit_landmarks.len(),32);
    assert!(candidate.holdout.passed);assert!(candidate.fit_rms_px<1e-5);
    let frozen=candidate.frozen_calibration([8;32])?;
    assert_eq!(frozen.camera.image_domain,[3;32]);assert_eq!(frozen.pose,candidate.pose);
    let tracking=candidate.bind_tracking_camera(&twin,TrackingCameraBinding{camera:7,calibration:9,image_domain:11,
        image_domain_digest:[3;32],clock:13,validity:[100,200],error:Some(fss_twin::ProjectionError{centre:[0.1;3],rotation_entry:0.001,focal:[0.1;2],principal:[0.1;2]})})?;
    assert_eq!(tracking.camera,7);assert_eq!(tracking.calibration,9);assert_eq!(tracking.pose,candidate.pose);
    assert_eq!(tracking.intrinsics,candidate.intrinsics);
    let mut wrong=TrackingCameraBinding{camera:7,calibration:9,image_domain:11,image_domain_digest:[4;32],clock:13,validity:[100,200],error:None};
    assert!(matches!(candidate.bind_tracking_camera(&twin,wrong),Err(RegistrationCandidateError::InvalidBinding)));
    wrong.image_domain_digest=[3;32];wrong.camera=0;
    assert!(matches!(candidate.bind_tracking_camera(&twin,wrong),Err(RegistrationCandidateError::InvalidBinding)));
    wrong.camera=7;
    wrong.error=Some(fss_twin::ProjectionError{rotation_entry:f64::NAN,..fss_twin::ProjectionError::EXACT});
    assert!(matches!(candidate.bind_tracking_camera(&twin,wrong),Err(RegistrationCandidateError::InvalidBinding)));
    Ok(())
}

#[test]
fn validation_from_another_scan_cannot_be_rebound()->Test{
    let twin=common::twin(&[0.0],None)?;let mut budget=WorkBudget::new(2_000_000_000);let atlas=atlas(&twin,&mut budget)?;
    let query=frame(2,true,&mut budget)?;
    let first=localize_focal_scan(&atlas,&twin,&query,[3;32],MatchOptions{maximum_distance:0,ratio_percent:80},scan(),&mut budget)?;
    let second=localize_focal_scan(&atlas,&twin,&query,[3;32],MatchOptions{maximum_distance:0,ratio_percent:80},scan(),&mut budget)?;
    let FocalLocalizationOutcome::Scan(second_scan)=&second.outcome else{return Err("no second scan".into());};
    let second_validation=second_scan.validate_all_candidates(twin.basis(),&holdout(),0.01,&mut budget)?;
    assert!(matches!(select_unique_focal_registration(&twin,&atlas,&first,&second_validation),Err(RegistrationCandidateError::ValidationMismatch)));
    Ok(())
}

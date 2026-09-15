#![forbid(unsafe_code)]
mod common;

use std::error::Error;
use fss_geometry::{Correspondence,PoseSolverOptions,WorkBudget};
use fss_twin::localization::*;
use fss_twin::radial_localization::*;
use fss_twin::rectification::{LensDistortion,LumaRange};
use fss_twin::validated_radial_registration::*;
use fss_twin::validated_registration::TrackingCameraBinding;

type Test=Result<(),Box<dyn Error>>;const FX:f64=800.;const K1:f64=0.1;
fn descriptor(id:u64)->BinaryDescriptor{BinaryDescriptor([id.wrapping_mul(0x9e3779b97f4a7c15),!id,id.rotate_left(17),id.wrapping_mul(0xd6e8feb86659fd93)])}
fn world(id:u64)->[f64;3]{let n=id as f64;[2.*(n*.7).sin(),1.5*(n*1.3).cos(),1.2*(n*.31).sin()]}
fn raw_pixel(w:[f64;3])->[f64;2]{let x=.8*w[0]+.6*w[2]+.3;let y=w[1]-.4;let z=-.6*w[0]+.8*w[2]+8.;let xu=x/z;let yu=y/z;let q=xu*xu+yu*yu;let d=1.+K1*q;[FX*xu*d+960.,820.*yu*d+540.]}
fn frame(exposure:u8,query:bool,budget:&mut WorkBudget<'_>)->Result<FeatureFrame,LocalizationError>{
    let features=(1..=32).map(|id|ImageFeature{id,pixel:if query{raw_pixel(world(id))}else{[60.+id as f64*20.,80.+(id%10) as f64*40.]},descriptor:descriptor(id)}).collect();
    FeatureFrame::new(ImageIdentity{exposure:[exposure;32],pixels:[exposure.wrapping_add(30);32],image_domain:if query{[6;32]}else{[3;32]},dimensions:[1920,1080]},[9;32],features,budget)
}
fn atlas(twin:&fss_twin::PropertyTwin,budget:&mut WorkBudget<'_>)->Result<LocalizationAtlas,Box<dyn Error>>{
    let reference=frame(1,false,budget)?;let landmarks=(1..=32).map(|id|AtlasLandmark{id,physical_group:id,feature:0,world:world(id),evidence:[7;32],error:None}).collect();
    let bindings=(1..=32).map(|id|AtlasBinding{landmark:id,reference:1,image_feature:id}).collect();
    Ok(LocalizationAtlas::new(twin,landmarks,vec![AtlasReference{id:1,frame:reference}],bindings,budget)?)
}
fn options()->RadialFocalScanOptions{RadialFocalScanOptions{minimum_fx_px:400.,maximum_fx_px:1600.,focal_samples:17,y_over_x:820./800.,principal_point:[960.,540.],minimum_k1:-.2,maximum_k1:.2,k1_samples:17,maximum_undistorted_radius:2.,pose:PoseSolverOptions{ransac_trials:0,..PoseSolverOptions::default()}}}
fn holdout()->Vec<Correspondence>{(101..=112).map(|id|Correspondence{landmark:id,physical_group:id,world:world(id),pixel:raw_pixel(world(id))}).collect()}

#[test]
fn unique_lens_pose_compiles_rectification_and_tracking_generation()->Test{
    let twin=common::twin(&[0.0],None)?;let mut budget=WorkBudget::new(6_000_000_000);let atlas=atlas(&twin,&mut budget)?;let query=frame(2,true,&mut budget)?;
    let localization=localize_radial_focal_scan(&atlas,&twin,&query,MatchOptions{maximum_distance:0,ratio_percent:80},options(),&mut budget)?;
    let RadialLocalizationOutcome::Scan(scan)=&localization.outcome else{return Err("no scan".into());};
    let validation=scan.validate_all_candidates(&holdout(),.01,&mut budget)?;
    let candidate=select_unique_radial_registration(&twin,&atlas,&localization,&validation)?;
    assert!((candidate.raw_intrinsics.focal_lengths()[0]-FX).abs()<1e-9);assert!((candidate.k1-K1).abs()<1e-12);
    let plan=candidate.compile_rectification([8;32],LumaRange::Full,&mut budget)?;
    assert_eq!(plan.spec().source_domain,[6;32]);assert_ne!(plan.output_domain(),[6;32]);
    assert_eq!(plan.spec().distortion,LensDistortion::BrownConrady{radial:[K1,0.,0.],tangential:[0.,0.]});
    let tracking=candidate.bind_tracking_camera(&twin,&plan,TrackingCameraBinding{camera:7,calibration:9,image_domain:11,image_domain_digest:plan.output_domain(),clock:13,validity:[100,200],error:Some(.1)})?;
    assert_eq!(tracking.camera,7);assert_eq!(tracking.intrinsics,candidate.raw_intrinsics);assert_eq!(tracking.pose,candidate.pose);
    let frozen=candidate.frozen_calibration(&plan,[8;32])?;
    assert_eq!(frozen.camera.image_domain,plan.output_domain());assert_eq!(frozen.pose,candidate.pose);
    Ok(())
}

#[test]
fn wrong_derived_domain_cannot_bind_tracking_snapshot()->Test{
    let twin=common::twin(&[0.0],None)?;let mut budget=WorkBudget::new(6_000_000_000);let atlas=atlas(&twin,&mut budget)?;let query=frame(2,true,&mut budget)?;
    let localization=localize_radial_focal_scan(&atlas,&twin,&query,MatchOptions{maximum_distance:0,ratio_percent:80},options(),&mut budget)?;
    let RadialLocalizationOutcome::Scan(scan)=&localization.outcome else{return Err("no scan".into());};let validation=scan.validate_all_candidates(&holdout(),.01,&mut budget)?;
    let candidate=select_unique_radial_registration(&twin,&atlas,&localization,&validation)?;let plan=candidate.compile_rectification([8;32],LumaRange::Full,&mut budget)?;
    assert!(matches!(candidate.bind_tracking_camera(&twin,&plan,TrackingCameraBinding{camera:7,calibration:9,image_domain:11,image_domain_digest:[9;32],clock:13,validity:[100,200],error:None}),Err(RadialRegistrationError::InvalidBinding)));
    Ok(())
}

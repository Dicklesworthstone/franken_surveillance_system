#![forbid(unsafe_code)]
mod common;

use std::error::Error;
use std::sync::atomic::AtomicBool;
use fss_geometry::{Correspondence,GeometryError,PoseSolverOptions,WorkBudget};
use fss_twin::localization::*;
use fss_twin::radial_localization::*;

type Test=Result<(),Box<dyn Error>>;
const TRUE_FX:f64=800.0;const TRUE_K1:f64=0.1;
fn descriptor(id:u64)->BinaryDescriptor{BinaryDescriptor([id.wrapping_mul(0x9e3779b97f4a7c15),!id,id.rotate_left(17),id.wrapping_mul(0xd6e8feb86659fd93)])}
fn world(id:u64)->[f64;3]{let n=id as f64;[2.0*(n*0.7).sin(),1.5*(n*1.3).cos(),1.2*(n*0.31).sin()]}
fn raw_pixel(w:[f64;3],fx:f64,k1:f64)->[f64;2]{
    let x=0.8*w[0]+0.6*w[2]+0.3;let y=w[1]-0.4;let z=-0.6*w[0]+0.8*w[2]+8.0;
    let xu=x/z;let yu=y/z;let r2=xu*xu+yu*yu;let factor=1.0+k1*r2;
    [fx*xu*factor+960.0,fx*(820.0/800.0)*yu*factor+540.0]
}
fn frame(exposure:u8,query:bool,count:u64,budget:&mut WorkBudget<'_>)->Result<FeatureFrame,LocalizationError>{
    let features=(1..=count).map(|id|ImageFeature{id,pixel:if query{raw_pixel(world(id),TRUE_FX,TRUE_K1)}else{[60.0+id as f64*20.0,80.0+(id%10) as f64*40.0]},descriptor:descriptor(id)}).collect();
    FeatureFrame::new(ImageIdentity{exposure:[exposure;32],pixels:[exposure.wrapping_add(30);32],image_domain:if query{[6;32]}else{[3;32]},dimensions:[1920,1080]},[9;32],features,budget)
}
fn atlas(twin:&fss_twin::PropertyTwin,budget:&mut WorkBudget<'_>)->Result<LocalizationAtlas,Box<dyn Error>>{
    let reference=frame(1,false,32,budget)?;
    let landmarks=(1..=32).map(|id|AtlasLandmark{id,physical_group:id,feature:0,world:world(id),evidence:[7;32],error:None}).collect();
    let bindings=(1..=32).map(|id|AtlasBinding{landmark:id,reference:1,image_feature:id}).collect();
    Ok(LocalizationAtlas::new(twin,landmarks,vec![AtlasReference{id:1,frame:reference}],bindings,budget)?)
}
fn options()->RadialFocalScanOptions{RadialFocalScanOptions{minimum_fx_px:400.0,maximum_fx_px:1600.0,focal_samples:17,y_over_x:820.0/800.0,principal_point:[960.0,540.0],minimum_k1:-0.2,maximum_k1:0.2,k1_samples:17,maximum_undistorted_radius:2.0,pose:PoseSolverOptions{ransac_trials:0,..PoseSolverOptions::default()}}}
fn holdout()->Vec<Correspondence>{(101..=112).map(|id|Correspondence{landmark:id,physical_group:id,world:world(id),pixel:raw_pixel(world(id),TRUE_FX,TRUE_K1)}).collect()}

#[test]
fn exact_distorted_matches_recover_true_focal_and_k1_sample()->Test{
    let twin=common::twin(&[0.0],None)?;let mut budget=WorkBudget::new(4_000_000_000);let atlas=atlas(&twin,&mut budget)?;let query=frame(2,true,32,&mut budget)?;
    let result=localize_radial_focal_scan(&atlas,&twin,&query,MatchOptions{maximum_distance:0,ratio_percent:80},options(),&mut budget)?;
    assert_eq!(result.matches.correspondences.len(),32);
    let RadialLocalizationOutcome::Scan(scan)=result.outcome else{return Err("no radial scan".into());};
    let sample=scan.samples.iter().find(|s|s.focal_index==8&&s.k1_index==12).ok_or("true sample missing")?;
    assert!((sample.intrinsics.focal_lengths()[0]-TRUE_FX).abs()<1e-9);assert!((sample.k1-TRUE_K1).abs()<1e-12);
    let RadialSampleOutcome::Candidates(search)=&sample.outcome else{return Err("true lens sample failed".into());};
    assert_eq!(search.candidates()[0].inlier_landmarks().len(),32);assert!(search.candidates()[0].rms_px()<1e-5);
    Ok(())
}

#[test]
fn held_out_raw_landmarks_select_true_lens_pose_without_refit()->Test{
    let twin=common::twin(&[0.0],None)?;let mut budget=WorkBudget::new(5_000_000_000);let atlas=atlas(&twin,&mut budget)?;let query=frame(2,true,32,&mut budget)?;
    let result=localize_radial_focal_scan(&atlas,&twin,&query,MatchOptions{maximum_distance:0,ratio_percent:80},options(),&mut budget)?;
    let RadialLocalizationOutcome::Scan(scan)=result.outcome else{return Err("no radial scan".into());};
    let validation=scan.validate_all_candidates(&holdout(),0.01,&mut budget)?;
    let (sample_index,candidate)=validation.unique_passing_candidate().ok_or("lens not uniquely validated")?;
    assert_eq!(candidate,0);let sample=&scan.samples[sample_index];
    assert_eq!((sample.focal_index,sample.k1_index),(8,12));
    Ok(())
}

#[test]
fn noninvertible_candidates_are_retained_as_lens_failures()->Test{
    let twin=common::twin(&[0.0],None)?;let mut budget=WorkBudget::new(4_000_000_000);let atlas=atlas(&twin,&mut budget)?;let query=frame(2,true,32,&mut budget)?;
    let result=localize_radial_focal_scan(&atlas,&twin,&query,MatchOptions{maximum_distance:0,ratio_percent:80},options(),&mut budget)?;
    let RadialLocalizationOutcome::Scan(scan)=result.outcome else{return Err("no radial scan".into());};
    assert!(scan.samples.iter().any(|s|matches!(s.outcome,RadialSampleOutcome::LensFailure(RadialLensFailure::NonInvertible))));
    Ok(())
}

#[test]
fn cancellation_and_resource_exhaustion_abort_complete_scan()->Test{
    let twin=common::twin(&[0.0],None)?;let mut setup=WorkBudget::new(100_000_000);let atlas=atlas(&twin,&mut setup)?;let query=frame(2,true,32,&mut setup)?;
    let flag=AtomicBool::new(true);
    assert!(matches!(localize_radial_focal_scan(&atlas,&twin,&query,MatchOptions{maximum_distance:0,ratio_percent:80},options(),&mut WorkBudget::cancellable(4_000_000_000,&flag)),Err(LocalizationError::Geometry(GeometryError::Cancelled))));
    assert!(matches!(localize_radial_focal_scan(&atlas,&twin,&query,MatchOptions{maximum_distance:0,ratio_percent:80},options(),&mut WorkBudget::new(1)),Err(LocalizationError::Geometry(GeometryError::BudgetExhausted))));
    Ok(())
}

#![forbid(unsafe_code)]
mod common;

use std::error::Error;
use fss_geometry::{FocalSampleOutcome,FocalScanOptions,PoseSolverOptions,WorkBudget};
use fss_twin::focal_localization::*;
use fss_twin::localization::*;

type Test=Result<(),Box<dyn Error>>;
fn descriptor(id:u64)->BinaryDescriptor{
    BinaryDescriptor([id.wrapping_mul(0x9e3779b97f4a7c15),!id,id.rotate_left(17),id.wrapping_mul(0xd6e8feb86659fd93)])
}
fn world(id:u64)->[f64;3]{
    let n=id as f64;
    [2.0*(n*0.7).sin(),1.5*(n*1.3).cos(),1.2*(n*0.31).sin()]
}
fn query_pixel(w:[f64;3])->[f64;2]{
    let x=0.8*w[0]+0.6*w[2]+0.3;
    let y=w[1]-0.4;
    let z=-0.6*w[0]+0.8*w[2]+8.0;
    [800.0*x/z+960.0,820.0*y/z+540.0]
}
fn frame(exposure:u8,query:bool,budget:&mut WorkBudget<'_>)->Result<FeatureFrame,LocalizationError>{
    let features=(1..=32).map(|id|ImageFeature{id,pixel:if query{query_pixel(world(id))}else{[40.0+id as f64*20.0,100.0+(id%8) as f64*40.0]},descriptor:descriptor(id)}).collect();
    FeatureFrame::new(ImageIdentity{exposure:[exposure;32],pixels:[exposure.wrapping_add(20);32],image_domain:[3;32],dimensions:[1920,1080]},[9;32],features,budget)
}
fn atlas(twin:&fss_twin::PropertyTwin,budget:&mut WorkBudget<'_>)->Result<LocalizationAtlas,Box<dyn Error>>{
    let reference=frame(1,false,budget)?;
    let landmarks=(1..=32).map(|id|AtlasLandmark{id,physical_group:id,feature:0,world:world(id),evidence:[7;32],error:None}).collect();
    let bindings=(1..=32).map(|id|AtlasBinding{landmark:id,reference:1,image_feature:id}).collect();
    Ok(LocalizationAtlas::new(twin,landmarks,vec![AtlasReference{id:1,frame:reference}],bindings,budget)?)
}
fn scan()->FocalScanOptions{
    FocalScanOptions{minimum_fx_px:400.0,maximum_fx_px:1600.0,y_over_x:820.0/800.0,
        principal_point:[960.0,540.0],samples:33,pose:PoseSolverOptions{ransac_trials:0,..PoseSolverOptions::default()}}
}

#[test]
fn exact_image_matches_flow_into_unknown_focal_scan_without_supplied_correspondences()->Test{
    let twin=common::twin(&[0.0],None)?; let mut budget=WorkBudget::new(800_000_000);
    let atlas=atlas(&twin,&mut budget)?; let query=frame(2,true,&mut budget)?;
    let result=localize_focal_scan(&atlas,&twin,&query,[3;32],MatchOptions{maximum_distance:0,ratio_percent:80},scan(),&mut budget)?;
    assert_eq!(result.matches.correspondences.len(),32);
    let FocalLocalizationOutcome::Scan(scan)=result.outcome else{return Err("focal scan not produced".into());};
    assert_eq!(scan.samples().len(),33);
    let FocalSampleOutcome::Candidates(search)=scan.samples()[16].outcome() else{return Err("true focal sample failed".into());};
    assert!((scan.samples()[16].intrinsics().focal_lengths()[0]-800.0).abs()<1e-9);
    assert_eq!(search.candidates()[0].inlier_landmarks().len(),32);
    assert!(search.candidates()[0].rms_px()<1e-5);
    Ok(())
}

#[test]
fn reference_reuse_wrong_domain_and_insufficient_matches_do_not_invent_scan()->Test{
    let twin=common::twin(&[0.0],None)?; let mut budget=WorkBudget::new(100_000_000); let atlas=atlas(&twin,&mut budget)?;
    let reused=frame(1,true,&mut budget)?;
    assert!(matches!(localize_focal_scan(&atlas,&twin,&reused,[3;32],MatchOptions{maximum_distance:0,ratio_percent:80},scan(),&mut budget),Err(LocalizationError::ReferenceExposure)));
    let query=frame(2,true,&mut budget)?;
    assert!(matches!(localize_focal_scan(&atlas,&twin,&query,[4;32],MatchOptions{maximum_distance:0,ratio_percent:80},scan(),&mut budget),Err(LocalizationError::BasisMismatch)));
    let sparse_features=query.features()[..5].to_vec();
    let sparse=FeatureFrame::new(query.identity(),query.descriptor_domain(),sparse_features,&mut budget)?;
    let result=localize_focal_scan(&atlas,&twin,&sparse,[3;32],MatchOptions{maximum_distance:0,ratio_percent:80},scan(),&mut budget)?;
    assert!(matches!(result.outcome,FocalLocalizationOutcome::InsufficientMatches{found:5,..}));
    Ok(())
}

#![forbid(unsafe_code)]
//! Native gray focal localization contracts through the composed extraction route.
mod common;

use std::error::Error;
use fss_core::ContentDigest;
use fss_geometry::{FocalSampleOutcome,FocalScanOptions,PoseSolverOptions,WorkBudget};
use fss_twin::focal_localization::*;
use fss_twin::localization::*;
use fss_twin::localization::native::*;

type Test=Result<(),Box<dyn Error>>;
fn texture()->Vec<u8>{
    let mut state=1973_u32;
    (0..96*96).map(|_|{state=state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);20+((state>>16)%180) as u8}).collect()
}
fn rotate(pixels:&[u8])->Vec<u8>{
    let mut output=vec![0;pixels.len()];
    for y in 0..96{for x in 0..96{output[x*96+95-y]=pixels[y*96+x];}}
    output
}
fn identity(exposure:u8,pixels:&[u8])->ImageIdentity{
    ImageIdentity{exposure:[exposure;32],pixels:ContentDigest::sha256(pixels).bytes(),image_domain:[3;32],dimensions:[96,96]}
}
fn scan()->FocalScanOptions{
    FocalScanOptions{minimum_fx_px:40.0,maximum_fx_px:160.0,y_over_x:1.0,principal_point:[48.0,48.0],samples:17,
        pose:PoseSolverOptions{ransac_trials:0,..PoseSolverOptions::default()}}
}

#[test]
fn raw_pixels_localize_without_query_correspondences_or_focal_length()->Test{
    let twin=common::twin(&[0.0],None)?; let pixels=texture(); let query_pixels=rotate(&pixels); let mask=vec![1;pixels.len()];
    let mut budget=WorkBudget::new(2_000_000_000);
    let reference_image=GrayImage::new(identity(1,&pixels),&pixels,&mask,&mut budget)?;
    let extraction=ExtractionOptions{maximum_features:200,..ExtractionOptions::default()};
    let reference=extract_gray(&reference_image,extraction,&mut budget)?.frame;
    let mut landmarks=Vec::new(); let mut bindings=Vec::new();
    for (i,f) in reference.features().iter().enumerate(){
        let depth=6.0+(i%7) as f64*0.5;
        landmarks.push(AtlasLandmark{id:i as u64+1,physical_group:i as u64+1,feature:0,
            world:[(f.pixel[0]-48.0)*depth/80.0,(f.pixel[1]-48.0)*depth/80.0,depth],evidence:[4;32],error:None});
        bindings.push(AtlasBinding{landmark:i as u64+1,reference:1,image_feature:f.id});
    }
    let atlas=LocalizationAtlas::new(&twin,landmarks,vec![AtlasReference{id:1,frame:reference}],bindings,&mut budget)?;
    let query=GrayImage::new(identity(2,&query_pixels),&query_pixels,&mask,&mut budget)?;
    let result=localize_gray_focal_scan(&atlas,&twin,&query,GrayFocalScanControls{
        expected_image_domain:[3;32],extraction,
        matching:MatchOptions{maximum_distance:0,..MatchOptions::default()},scan:scan()},&mut budget)?;
    assert!(result.extraction.frame.features().len()>=8);
    assert!(result.localization.matches.correspondences.len()>=8);
    let FocalLocalizationOutcome::Scan(scan)=result.localization.outcome else{return Err("no focal scan".into());};
    let true_sample=&scan.samples()[8];
    assert!((true_sample.intrinsics().focal_lengths()[0]-80.0).abs()<1e-9);
    let FocalSampleOutcome::Candidates(search)=true_sample.outcome() else{return Err("true focal failed".into());};
    assert!(search.candidates()[0].rms_px()<1e-4);
    let expected=[[0.0,-1.0,0.0],[1.0,0.0,0.0],[0.0,0.0,1.0]];
    for (a,b) in search.candidates()[0].pose().rotation().iter().flatten().zip(expected.iter().flatten()){
        assert!((a-b).abs()<1e-4);
    }
    Ok(())
}

#[test]
fn masked_raw_query_cannot_manufacture_focal_evidence()->Test{
    let twin=common::twin(&[0.0],None)?; let pixels=texture(); let query_pixels=rotate(&pixels); let allowed=vec![1;pixels.len()];
    let mut budget=WorkBudget::new(1_000_000_000);
    let reference_image=GrayImage::new(identity(1,&pixels),&pixels,&allowed,&mut budget)?;
    let extraction=ExtractionOptions{maximum_features:200,..ExtractionOptions::default()};
    let reference=extract_gray(&reference_image,extraction,&mut budget)?.frame;
    let mut landmarks=Vec::new();let mut bindings=Vec::new();
    for (i,f) in reference.features().iter().enumerate(){
        let depth=6.0+(i%7) as f64*0.5;
        landmarks.push(AtlasLandmark{id:i as u64+1,physical_group:i as u64+1,feature:0,
            world:[(f.pixel[0]-48.0)*depth/80.0,(f.pixel[1]-48.0)*depth/80.0,depth],evidence:[4;32],error:None});
        bindings.push(AtlasBinding{landmark:i as u64+1,reference:1,image_feature:f.id});
    }
    let atlas=LocalizationAtlas::new(&twin,landmarks,vec![AtlasReference{id:1,frame:reference}],bindings,&mut budget)?;
    let denied=vec![0;query_pixels.len()];
    let query=GrayImage::new(identity(2,&query_pixels),&query_pixels,&denied,&mut budget)?;
    let result=localize_gray_focal_scan(&atlas,&twin,&query,GrayFocalScanControls{
        expected_image_domain:[3;32],extraction,matching:MatchOptions::default(),scan:scan()},&mut budget)?;
    assert_eq!(result.extraction.frame.features().len(),0);
    assert!(matches!(result.localization.outcome,FocalLocalizationOutcome::InsufficientMatches{found:0,..}));
    Ok(())
}

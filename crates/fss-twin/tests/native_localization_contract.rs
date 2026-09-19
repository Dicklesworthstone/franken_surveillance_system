#![forbid(unsafe_code)]
//! Native localization contract contract tests.
mod common;

use std::error::Error;
use std::sync::atomic::AtomicBool;
use fss_core::ContentDigest;
use fss_geometry::{GeometryError,PinholeIntrinsics,PoseSolverOptions,WorkBudget};
use fss_twin::localization::*;
use fss_twin::localization::native::*;

type Test=Result<(),Box<dyn Error>>;
fn texture()->Vec<u8> {
    let mut state=1973_u32;
    (0..96*96).map(|_|{state=state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        20+((state>>16)%180) as u8}).collect()
}
fn identity(exposure:u8,pixels:&[u8])->ImageIdentity {
    ImageIdentity{exposure:[exposure;32],pixels:ContentDigest::sha256(pixels).bytes(),image_domain:[3;32],dimensions:[96,96]}
}
fn rotate(pixels:&[u8])->Vec<u8> {
    let mut output=vec![0;pixels.len()];
    for y in 0..96 {for x in 0..96 {output[x*96+95-y]=pixels[y*96+x];}}
    output
}
#[test]
fn descriptor_has_an_independent_golden_and_rotation_brightness_controls()->Test {
    let pixels=texture();let rotated=rotate(&pixels);
    let brighter:Vec<_>=pixels.iter().map(|x|*x+20).collect();let mask=vec![1;pixels.len()];
    let mut budget=WorkBudget::new(10_000_000);
    let source=GrayImage::new(identity(1,&pixels),&pixels,&mask,&mut budget)?;
    let rotated=GrayImage::new(identity(2,&rotated),&rotated,&mask,&mut budget)?;
    let brighter=GrayImage::new(identity(3,&brighter),&brighter,&mask,&mut budget)?;
    let original=describe_reference_pixels(&source,&[ReferencePixel{id:1,column:31,row:25}],&mut budget)?;
    let turned=describe_reference_pixels(&rotated,&[ReferencePixel{id:1,column:70,row:31}],&mut budget)?;
    let lit=describe_reference_pixels(&brighter,&[ReferencePixel{id:1,column:31,row:25}],&mut budget)?;
    let d=original.features()[0].descriptor;
    assert_eq!(d.0,[7446008588468777431,4775082772142637252,7157827042248088871,8533386832858067528]);
    assert_eq!(d,turned.features()[0].descriptor);assert_eq!(d,lit.features()[0].descriptor);
    Ok(())
}
#[test]
fn detected_and_explicit_reference_descriptors_are_identical()->Test {
    let pixels=texture();let mask=vec![1;pixels.len()];let mut budget=WorkBudget::new(100_000_000);
    let image=GrayImage::new(identity(1,&pixels),&pixels,&mask,&mut budget)?;
    let extracted=extract_gray(&image,ExtractionOptions::default(),&mut budget)?;
    assert!(extracted.frame.features().len()>8);
    let points:Vec<_>=extracted.frame.features().iter().map(|f|ReferencePixel{id:f.id,
        column:f.pixel[0] as u32,row:f.pixel[1] as u32}).collect();
    let described=describe_reference_pixels(&image,&points,&mut budget)?;
    assert_eq!(described.features(),extracted.frame.features());
    assert_eq!(described.descriptor_domain(),descriptor_domain());
    Ok(())
}
#[test]
fn masked_pixels_cannot_enter_descriptor_neighborhoods()->Test {
    let pixels=texture();let mut mask=vec![1;pixels.len()];mask[40*96+55]=0;
    let mut budget=WorkBudget::new(100_000_000);
    let image=GrayImage::new(identity(1,&pixels),&pixels,&mask,&mut budget)?;
    assert!(matches!(describe_reference_pixels(&image,&[ReferencePixel{id:1,column:40,row:40}],&mut budget),Err(LocalizationError::InvalidInput)));
    let result=extract_gray(&image,ExtractionOptions::default(),&mut budget)?;
    for feature in result.frame.features() {
        let x=feature.pixel[0] as usize;let y=feature.pixel[1] as usize;
        assert!(x.abs_diff(55)>16 || y.abs_diff(40)>16);
    }
    Ok(())
}
#[test]
fn blank_and_fully_masked_images_do_not_invent_features()->Test {
    let pixels=vec![100;96*96];let allowed=vec![1;96*96];let denied=vec![0;96*96];
    let mut budget=WorkBudget::new(100_000_000);
    for mask in [&allowed,&denied] {
        let image=GrayImage::new(identity(1,&pixels),&pixels,mask,&mut budget)?;
        let result=extract_gray(&image,ExtractionOptions::default(),&mut budget)?;
        assert!(result.frame.features().is_empty());assert_eq!(result.selection.local_maxima,0);
    }
    Ok(())
}
#[test]
fn pixel_hash_and_mask_shape_are_checked_before_use()->Test {
    let pixels=texture();let mut changed=pixels.clone();changed[0]^=1;
    let mut mask=vec![1;pixels.len()];let mut budget=WorkBudget::new(1_000_000);
    assert!(matches!(GrayImage::new(identity(1,&pixels),&changed,&mask,&mut budget),Err(LocalizationError::BasisMismatch)));
    mask[0]=2;
    assert!(matches!(GrayImage::new(identity(1,&pixels),&pixels,&mask,&mut budget),Err(LocalizationError::InvalidInput)));
    assert!(matches!(GrayImage::new(identity(1,&pixels),&pixels,&mask[..20],&mut budget),Err(LocalizationError::InvalidInput)));
    Ok(())
}
#[test]
fn limits_omissions_and_cancellation_are_explicit()->Test {
    let pixels=texture();let mask=vec![1;pixels.len()];let mut budget=WorkBudget::new(100_000_000);
    let image=GrayImage::new(identity(1,&pixels),&pixels,&mask,&mut budget)?;
    let options=ExtractionOptions{maximum_features:5,..ExtractionOptions::default()};
    let a=extract_gray(&image,options,&mut budget)?;let b=extract_gray(&image,options,&mut budget)?;
    assert_eq!(a.frame.features(),b.frame.features());assert_eq!(a.selection,b.selection);
    assert_eq!(a.selection.selected,5);assert!(a.selection.omitted>0);
    assert_eq!(a.selection.selected+a.selection.omitted,a.selection.local_maxima);
    assert!(matches!(extract_gray(&image,options,&mut WorkBudget::new(1)),Err(LocalizationError::Geometry(GeometryError::BudgetExhausted))));
    let flag=AtomicBool::new(true);
    assert!(matches!(extract_gray(&image,options,&mut WorkBudget::cancellable(100_000_000,&flag)),Err(LocalizationError::Geometry(GeometryError::Cancelled))));
    assert!(matches!(describe_reference_pixels(&image,&[ReferencePixel{id:1,column:u32::MAX,row:0}],&mut budget),Err(LocalizationError::InvalidInput)));
    Ok(())
}
#[test]
fn raw_pixels_to_rotated_camera_pose_without_query_correspondences()->Test {
    let twin=common::twin(&[0.0],None)?;
    let pixels=texture();let query_pixels=rotate(&pixels);let mask=vec![1;pixels.len()];
    let mut budget=WorkBudget::new(1_000_000_000);
    let reference_image=GrayImage::new(identity(1,&pixels),&pixels,&mask,&mut budget)?;
    let extraction=ExtractionOptions{maximum_features:200,..ExtractionOptions::default()};
    let reference=extract_gray(&reference_image,extraction,&mut budget)?.frame;
    let mut landmarks=Vec::new();let mut bindings=Vec::new();
    for (i,f) in reference.features().iter().enumerate() {
        let depth=6.0+(i%7) as f64*0.5;
        landmarks.push(AtlasLandmark{id:i as u64+1,physical_group:i as u64+1,feature:0,
            world:[(f.pixel[0]-48.0)*depth/80.0,(f.pixel[1]-48.0)*depth/80.0,depth],evidence:[4;32],error:None});
        bindings.push(AtlasBinding{landmark:i as u64+1,reference:1,image_feature:f.id});
    }
    let atlas=LocalizationAtlas::new(&twin,landmarks,vec![AtlasReference{id:1,frame:reference}],bindings,&mut budget)?;
    let query=GrayImage::new(identity(2,&query_pixels),&query_pixels,&mask,&mut budget)?;
    let camera=LocalizationCamera{intrinsics:PinholeIntrinsics::new(96,96,80.0,80.0,48.0,48.0)?,image_domain:[3;32]};
    let result=localize_gray_frame(&atlas,&twin,&query,camera,ImageLocalizationOptions{extraction,
        matching:MatchOptions{maximum_distance:0,..MatchOptions::default()},
        solving:PoseSolverOptions{ransac_trials:0,..PoseSolverOptions::default()}},&mut budget)?;
    assert!(result.localization.matches.correspondences.len()>=8);
    let LocalizationOutcome::Candidates(search)=result.localization.outcome else {return Err("raw image did not localize".into());};
    assert_eq!(search.candidates().len(),1);
    let pose=search.candidates()[0].pose();let expected=[[0.0,-1.0,0.0],[1.0,0.0,0.0],[0.0,0.0,1.0]];
    for (a,b) in pose.rotation().iter().flatten().zip(expected.iter().flatten()) {assert!((a-b).abs()<1e-4);}
    assert!(pose.center().iter().all(|x|x.abs()<1e-4));
    Ok(())
}

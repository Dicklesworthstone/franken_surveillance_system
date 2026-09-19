#![forbid(unsafe_code)]
//! Localization contract contract tests.
mod common;

use std::error::Error;
use std::sync::atomic::AtomicBool;
use fss_core::ContentDigest;
use fss_geometry::{GeometryError, PinholeIntrinsics, PoseSolverOptions, RigidPose, WorkBudget};
use fss_twin::localization::*;
use fss_twin::PropertyTwin;

type Test = Result<(), Box<dyn Error>>;
fn descriptor(id: u64) -> BinaryDescriptor {
    let b = ContentDigest::sha256(&id.to_le_bytes()).bytes();
    BinaryDescriptor(std::array::from_fn(|i| {
        let j = i * 8;
        u64::from_le_bytes([b[j], b[j+1], b[j+2], b[j+3], b[j+4], b[j+5], b[j+6], b[j+7]])
    }))
}
fn camera() -> Result<LocalizationCamera, Box<dyn Error>> {
    Ok(LocalizationCamera { intrinsics: PinholeIntrinsics::new(320,240,120.0,120.0,160.0,120.0)?, image_domain:[3;32] })
}
fn identity(exposure: u8) -> ImageIdentity {
    ImageIdentity { exposure:[exposure;32], pixels:[2;32], image_domain:[3;32], dimensions:[320,240] }
}
fn points() -> Vec<AtlasLandmark> {
    (0..12).map(|i| AtlasLandmark { id:i+1, physical_group:i+101, feature:0,
        world:[(i%4) as f64*2.0-3.0,(i/4) as f64*1.5-1.5,(i%3) as f64+6.0],
        evidence:[4;32], error:None }).collect()
}
fn frame(points: &[AtlasLandmark], exposure: u8, pose: RigidPose) -> Result<FeatureFrame, Box<dyn Error>> {
    let k = camera()?.intrinsics;
    let features = points.iter().map(|p| Ok(ImageFeature { id:p.id, pixel:pose.project(k,p.world)?,
        descriptor:descriptor(p.id) })).collect::<Result<Vec<_>,GeometryError>>()?;
    Ok(FeatureFrame::new(identity(exposure),[9;32],features,&mut WorkBudget::new(1_000_000))?)
}
fn atlas(twin: &PropertyTwin, copies: u64) -> Result<LocalizationAtlas, Box<dyn Error>> {
    let points = points();
    let mut references = Vec::new();
    let mut bindings = Vec::new();
    for r in 1..=copies {
        references.push(AtlasReference { id:r, frame:frame(&points,r as u8,RigidPose::IDENTITY)? });
        for point in &points { bindings.push(AtlasBinding { landmark:point.id,reference:r,image_feature:point.id }); }
    }
    Ok(LocalizationAtlas::new(twin,points,references,bindings,&mut WorkBudget::new(5_000_000))?)
}

#[test]
fn multiview_observations_do_not_become_competing_landmarks() -> Test {
    let twin=common::twin(&[0.0],None)?;
    let atlas=atlas(&twin,3)?;
    let query=frame(&points(),100,RigidPose::IDENTITY)?;
    let report=atlas.match_frame(&twin,&query,MatchOptions::default(),&mut WorkBudget::new(1_000_000))?;
    assert_eq!(report.correspondences.len(),12);
    assert_eq!(report.decisions.len(),12);
    assert!(report.decisions.iter().all(|d|d.distance==0 && d.rejection.is_none()));
    assert_eq!(atlas.bindings().len(),36);
    assert!(atlas.landmarks().iter().all(|p|p.error.is_none()));
    Ok(())
}
#[test]
fn repeated_texture_is_rejected_in_both_directions() -> Test {
    let twin=common::twin(&[0.0],None)?;
    let atlas=atlas(&twin,1)?;
    let query=frame(&points(),100,RigidPose::IDENTITY)?;
    let mut features=query.features().to_vec();
    features.push(ImageFeature{id:100,pixel:[10.0,10.0],descriptor:features[0].descriptor});
    let duplicate=FeatureFrame::new(identity(100),[9;32],features,&mut WorkBudget::new(10_000))?;
    let report=atlas.match_frame(&twin,&duplicate,MatchOptions::default(),&mut WorkBudget::new(1_000_000))?;
    assert_eq!(report.correspondences.len(),11);
    assert_eq!(report.decisions.iter().filter(|d|d.rejection==Some(MatchRejection::NonMutual)).count(),2);
    Ok(())
}
#[test]
fn identical_descriptors_on_different_world_points_are_ambiguous() -> Test {
    let twin=common::twin(&[0.0],None)?;
    let p=points();
    let f=frame(&p,1,RigidPose::IDENTITY)?;
    let mut features=f.features().to_vec();features[1].descriptor=features[0].descriptor;
    let f=FeatureFrame::new(identity(1),[9;32],features,&mut WorkBudget::new(10_000))?;
    let bindings=p.iter().map(|p|AtlasBinding{landmark:p.id,reference:1,image_feature:p.id}).collect();
    let atlas=LocalizationAtlas::new(&twin,p.clone(),vec![AtlasReference{id:1,frame:f}],bindings,&mut WorkBudget::new(1_000_000))?;
    let report=atlas.match_frame(&twin,&frame(&p,100,RigidPose::IDENTITY)?,MatchOptions::default(),&mut WorkBudget::new(1_000_000))?;
    assert_eq!(report.decisions[0].rejection,Some(MatchRejection::Ambiguous));
    assert_eq!(report.decisions[0].runner_up_distance,Some(0));
    Ok(())
}
#[test]
fn image_matching_drives_the_real_pose_solver() -> Test {
    let twin=common::twin(&[0.0],None)?;
    let atlas=atlas(&twin,2)?;
    let expected=RigidPose::from_center([[1.0,0.0,0.0],[0.0,1.0,0.0],[0.0,0.0,1.0]],[0.3,-0.2,-0.4])?;
    let query=frame(&points(),100,expected)?;
    let output=atlas.localize(&twin,&query,camera()?,MatchOptions::default(),
        PoseSolverOptions{ransac_trials:0,..PoseSolverOptions::default()},&mut WorkBudget::new(100_000_000))?;
    assert_eq!(output.matches.correspondences.len(),12);
    let LocalizationOutcome::Candidates(search)=output.outcome else { return Err("expected a recovered pose".into()); };
    assert_eq!(search.candidates().len(),1);
    let actual=search.candidates()[0].pose().center();
    for (a,b) in actual.into_iter().zip(expected.center()) {assert!((a-b).abs()<1e-4);}
    Ok(())
}
#[test]
fn stale_package_same_local_basis_is_still_rejected() -> Test {
    let twin=common::twin(&[0.0],None)?;let other=common::twin(&[1.0],None)?;
    let atlas=atlas(&twin,1)?;let query=frame(&points(),100,RigidPose::IDENTITY)?;
    assert!(matches!(atlas.match_frame(&other,&query,MatchOptions::default(),&mut WorkBudget::new(100_000)),Err(LocalizationError::BasisMismatch)));
    let mut k=camera()?;k.image_domain=[5;32];
    assert!(matches!(atlas.localize(&twin,&query,k,MatchOptions::default(),PoseSolverOptions::default(),&mut WorkBudget::new(100_000)),Err(LocalizationError::BasisMismatch)));
    Ok(())
}
#[test]
fn generation_and_reference_exposure_cannot_be_silently_reused() -> Test {
    let twin=common::twin(&[0.0],None)?;let atlas=atlas(&twin,1)?;
    let query=frame(&points(),1,RigidPose::IDENTITY)?;
    assert!(matches!(atlas.localize(&twin,&query,camera()?,MatchOptions::default(),PoseSolverOptions::default(),&mut WorkBudget::new(100_000)),Err(LocalizationError::ReferenceExposure)));
    let incompatible=FeatureFrame::new(identity(100),[8;32],query.features().to_vec(),&mut WorkBudget::new(10_000))?;
    assert!(matches!(atlas.match_frame(&twin,&incompatible,MatchOptions::default(),&mut WorkBudget::new(100_000)),Err(LocalizationError::BasisMismatch)));
    Ok(())
}
#[test]
fn cancellations_and_exhaustion_are_errors_not_partial_poses() -> Test {
    let twin=common::twin(&[0.0],None)?;let atlas=atlas(&twin,1)?;
    let query=frame(&points(),100,RigidPose::IDENTITY)?;
    assert!(matches!(atlas.match_frame(&twin,&query,MatchOptions::default(),&mut WorkBudget::new(1)),Err(LocalizationError::Geometry(GeometryError::BudgetExhausted))));
    let flag=AtomicBool::new(true);
    assert!(matches!(atlas.localize(&twin,&query,camera()?,MatchOptions::default(),PoseSolverOptions::default(),&mut WorkBudget::cancellable(1_000_000,&flag)),Err(LocalizationError::Geometry(GeometryError::Cancelled))));
    Ok(())
}
#[test]
fn complete_input_validation_rejects_aliases_and_conflicting_bindings() -> Test {
    let twin=common::twin(&[0.0],None)?;
    let p=points();let reference=AtlasReference{id:1,frame:frame(&p,1,RigidPose::IDENTITY)?};
    let bindings:Vec<_>=p.iter().map(|p|AtlasBinding{landmark:p.id,reference:1,image_feature:p.id}).collect();
    let mut aliases=p.clone();aliases[1].physical_group=aliases[0].physical_group;
    assert!(matches!(LocalizationAtlas::new(&twin,aliases,vec![reference.clone()],bindings.clone(),&mut WorkBudget::new(1_000_000)),Err(LocalizationError::InvalidInput)));
    let mut bad=bindings.clone();bad[1].image_feature=bad[0].image_feature;
    assert!(matches!(LocalizationAtlas::new(&twin,p.clone(),vec![reference.clone()],bad,&mut WorkBudget::new(1_000_000)),Err(LocalizationError::InvalidInput)));
    let mut bad=bindings;bad[11].landmark=999;
    assert!(matches!(LocalizationAtlas::new(&twin,p,vec![reference],bad,&mut WorkBudget::new(1_000_000)),Err(LocalizationError::InvalidInput)));
    Ok(())
}
#[test]
fn atlas_fingerprint_is_input_order_independent_and_source_bound() -> Test {
    let twin=common::twin(&[0.0],None)?;let a=atlas(&twin,2)?;
    let mut points=a.landmarks().to_vec();points.reverse();
    let mut references=a.references().to_vec();references.reverse();
    let mut bindings=a.bindings().to_vec();bindings.reverse();
    let b=LocalizationAtlas::new(&twin,points.clone(),references.clone(),bindings.clone(),&mut WorkBudget::new(1_000_000))?;
    assert_eq!(a.digest(),b.digest());
    points[0].evidence=[12;32];
    let c=LocalizationAtlas::new(&twin,points,references,bindings,&mut WorkBudget::new(1_000_000))?;
    assert_ne!(a.digest(),c.digest());
    Ok(())
}
#[test]
fn empty_features_leave_an_explicit_unlocalized_result() -> Test {
    let twin=common::twin(&[0.0],None)?;let atlas=atlas(&twin,1)?;
    let empty=FeatureFrame::new(identity(100),[9;32],vec![],&mut WorkBudget::new(100))?;
    let result=atlas.localize(&twin,&empty,camera()?,MatchOptions::default(),PoseSolverOptions::default(),&mut WorkBudget::new(100_000))?;
    assert!(matches!(result.outcome,LocalizationOutcome::InsufficientMatches));
    assert!(result.matches.decisions.is_empty());
    Ok(())
}
#[test]
fn descriptor_distance_uses_all_256_bits() {
    let zero=BinaryDescriptor([0;4]);
    assert_eq!(zero.distance(BinaryDescriptor([u64::MAX;4])),256);
    for i in 0..256 {let mut words=[0;4];words[i/64]=1<<(i%64);assert_eq!(zero.distance(BinaryDescriptor(words)),1);}
}

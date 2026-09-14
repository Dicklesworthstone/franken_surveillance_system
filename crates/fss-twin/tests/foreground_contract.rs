#![forbid(unsafe_code)]
use std::error::Error;
use std::sync::atomic::AtomicBool;
use fss_core::ContentDigest;
use fss_geometry::{GeometryError, WorkBudget};
use fss_twin::foreground::*;
use fss_twin::localization::ImageIdentity;

type Test = Result<(), Box<dyn Error>>;
fn source(exposure: u8, pixels: &[u8], w: u32, h: u32) -> ForegroundSource {
    ForegroundSource { image: ImageIdentity { exposure: [exposure; 32],
        pixels: ContentDigest::sha256(pixels).bytes(), image_domain: [7; 32], dimensions: [w, h] },
        camera: 1, calibration: [9; 32], clock: 2, capture: [u64::from(exposure) * 10; 2] }
}
fn policy() -> ForegroundPolicy {
    ForegroundPolicy { minimum_change: 10, minimum_area: 2, maximum_regions: 32, widespread_per_mille: 750 }
}
fn background_policy() -> BackgroundPolicy {
    BackgroundPolicy { selection_evidence: [6; 32], validity: [0, 10000], maximum_spread: 4 }
}
fn model(w: u32, h: u32) -> Result<BackgroundModel, ForegroundError> {
    let n = (w * h) as usize; let a = vec![99; n]; let b = vec![100; n]; let c = vec![101; n];
    let mask = vec![1; n]; let mut budget = WorkBudget::new(10_000_000);
    let frames = [ForegroundFrame::new(source(1, &a, w, h), &a, &mask, &mut budget)?,
        ForegroundFrame::new(source(2, &b, w, h), &b, &mask, &mut budget)?,
        ForegroundFrame::new(source(3, &c, w, h), &c, &mask, &mut budget)?];
    BackgroundModel::build(&frames, background_policy(), &mut budget)
}
fn detect(m: &BackgroundModel, pixels: &[u8], mask: &[u8], w: u32, h: u32,
    p: ForegroundPolicy) -> Result<ForegroundReport, ForegroundError> {
    let mut budget = WorkBudget::new(10_000_000);
    let f = ForegroundFrame::new(source(4, pixels, w, h), pixels, mask, &mut budget)?;
    m.detect(&f, p, &mut budget)
}
#[test]
fn components_preserve_exact_occupancy_and_polarity() -> Test {
    let m = model(6, 5)?; let mask = vec![1; 30]; let mut q = vec![100; 30];
    for i in [7, 8, 13] { q[i] = 150; }
    for i in [22, 28] { q[i] = 30; }
    q[5] = 130;
    let r = detect(&m, &q, &mask, 6, 5, policy())?;
    assert_eq!(m.digest(), [224, 185, 14, 222, 239, 146, 176, 199, 11, 223, 149, 132, 58, 143, 7, 128, 58, 102, 175, 179, 188, 238, 102, 90, 201, 228, 250, 190, 194, 142, 39, 162]);
    assert_eq!(r.digest(), [62, 218, 88, 233, 123, 139, 58, 126, 27, 195, 57, 99, 47, 65, 238, 124, 123, 112, 187, 176, 31, 172, 25, 82, 186, 38, 52, 197, 79, 38, 108, 124]);
    assert_eq!(r.changed_pixels(), 6); assert_eq!(r.comparable_pixels(), 30);
    assert_eq!(r.small_component_count(), 1); assert_eq!(r.small_component_pixels(), 1);
    assert_eq!(r.regions().len(), 2); assert_eq!(r.assessment(), FrameAssessment::LocalChange);
    assert_eq!(r.regions()[0], ForegroundRegion { id: 8, area: 3, min: [1,1], max: [3,3],
        brighter: 3, darker: 0, touches_unknown: false, touches_edge: false });
    assert_eq!(r.regions()[1], ForegroundRegion { id: 23, area: 2, min: [4,3], max: [5,5],
        brighter: 0, darker: 2, touches_unknown: false, touches_edge: true });
    assert_eq!(r.component_labels()[5], 6); // the size-omitted component still exists
    assert_eq!(r.component_labels()[14], 0); // box contains background, not filled foreground
    assert_eq!(r.pixel_states()[28], 2);
    Ok(())
}
#[test]
fn stopped_appearance_does_not_get_absorbed_by_detection() -> Test {
    let m = model(6,5)?; let original = m.digest(); let mask = vec![1;30]; let mut q = vec![100;30];
    q[7] = 150; q[8] = 150;
    let mut budget = WorkBudget::new(10_000_000);
    for e in 4..100 {
        let f = ForegroundFrame::new(source(e,&q,6,5),&q,&mask,&mut budget)?;
        assert_eq!(m.detect(&f,policy(),&mut budget)?.changed_pixels(),2);
    }
    assert_eq!(m.digest(),original); Ok(())
}
#[test]
fn unstable_or_previously_private_pixels_remain_unknown() -> Test {
    let a=vec![100;4]; let b=vec![100,150,100,100]; let c=vec![100;4];
    let ma=vec![1,1,0,1]; let all=vec![1;4]; let mut budget=WorkBudget::new(100_000);
    let frames=[ForegroundFrame::new(source(1,&a,2,2),&a,&ma,&mut budget)?,
        ForegroundFrame::new(source(2,&b,2,2),&b,&all,&mut budget)?,
        ForegroundFrame::new(source(3,&c,2,2),&c,&all,&mut budget)?];
    let m=BackgroundModel::build(&frames,background_policy(),&mut budget)?;
    assert_eq!(m.known_pixels(),2);
    let q=vec![100,200,200,100]; let r=detect(&m,&q,&all,2,2,policy())?;
    assert_eq!(r.pixel_states(),[1,0,0,1]); assert_eq!(r.changed_pixels(),0);
    assert_eq!(r.comparable_pixels(),2);
    Ok(())
}
#[test]
fn mask_holes_split_regions_and_report_truncated_boundaries() -> Test {
    let m=model(5,3)?; let q=vec![200;15]; let mut mask=vec![1;15];
    for i in [2,7,12] {mask[i]=0;}
    let r=detect(&m,&q,&mask,5,3,policy())?;
    assert_eq!(r.regions().len(),2); assert_eq!(r.changed_pixels(),12);
    assert!(r.regions().iter().all(|r|r.touches_unknown && r.touches_edge));
    for i in [2,7,12] {assert_eq!(r.pixel_states()[i],0);assert_eq!(r.component_labels()[i],0);}
    assert_eq!(r.assessment(),FrameAssessment::WidespreadChange); Ok(())
}
#[test]
fn diagonal_neighbors_do_not_merge_and_small_changes_do_not_become_silence() -> Test {
    let m=model(3,3)?; let q=vec![200,100,100,100,200,100,100,100,200];
    let r=detect(&m,&q,&[1;9],3,3,policy())?;
    assert!(r.regions().is_empty());assert_eq!(r.small_component_count(),3);
    assert_eq!(r.small_component_pixels(),3);assert_eq!(r.assessment(),FrameAssessment::LocalChange);
    assert_eq!(r.component_labels(),[1,0,0,0,5,0,0,0,9]); Ok(())
}
#[test]
fn no_comparable_pixels_is_distinct_from_no_change() -> Test {
    let m=model(2,2)?; let q=[100;4];
    assert_eq!(detect(&m,&q,&[0;4],2,2,policy())?.assessment(),FrameAssessment::NoComparablePixels);
    assert_eq!(detect(&m,&q,&[1;4],2,2,policy())?.assessment(),FrameAssessment::NoAboveThresholdChange);
    Ok(())
}
#[test]
fn broad_change_retains_regions_and_never_assumes_safe_illumination() -> Test {
    let m=model(3,3)?;let r=detect(&m,&[200;9],&[1;9],3,3,policy())?;
    assert_eq!(r.assessment(),FrameAssessment::WidespreadChange);assert_eq!(r.regions()[0].area,9); Ok(())
}
#[test]
fn exact_envelope_thresholds_are_strict_at_both_ends() -> Test {
    let m=model(4,1)?;let r=detect(&m,&[89,88,111,112],&[1;4],4,1,
        ForegroundPolicy{minimum_area:1,..policy()})?;
    assert_eq!(r.pixel_states(),[1,2,1,3]); Ok(())
}
#[test]
fn duplicate_references_and_reference_query_reuse_are_rejected() -> Test {
    let p=[100;4];let mask=[1;4];let mut budget=WorkBudget::new(1_000_000);
    let frames=[ForegroundFrame::new(source(1,&p,2,2),&p,&mask,&mut budget)?,
        ForegroundFrame::new(source(2,&p,2,2),&p,&mask,&mut budget)?,
        ForegroundFrame::new(source(2,&p,2,2),&p,&mask,&mut budget)?];
    assert!(matches!(BackgroundModel::build(&frames,background_policy(),&mut budget),Err(ForegroundError::ReusedExposure)));
    let m=model(2,2)?;let mut s=source(2,&p,2,2);s.capture=[100;2];
    let q=ForegroundFrame::new(s,&p,&mask,&mut budget)?;
    assert!(matches!(m.detect(&q,policy(),&mut budget),Err(ForegroundError::ReusedExposure)));Ok(())
}
#[test]
fn source_basis_and_temporal_validity_cannot_be_reused() -> Test {
    let m=model(2,2)?;let p=[100;4];let mask=[1;4];let mut budget=WorkBudget::new(1_000_000);
    for field in 0..6 {
        let mut s=source(4,&p,2,2);
        match field {0=>s.camera=99,1=>s.calibration=[2;32],2=>s.clock=99,
            3=>s.image.image_domain=[4;32],4=>s.capture=[20;2],_=>s.capture=[9999,10001]}
        let f=ForegroundFrame::new(s,&p,&mask,&mut budget)?;
        assert!(m.detect(&f,policy(),&mut budget).is_err());
    } Ok(())
}
#[test]
fn malformed_pixels_and_masks_do_not_get_an_identity() -> Test {
    let p=[100;4];let mut budget=WorkBudget::new(10000);let mut s=source(4,&p,2,2);
    s.image.pixels=[8;32];
    assert!(matches!(ForegroundFrame::new(s,&p,&[1;4],&mut budget),Err(ForegroundError::BasisMismatch)));
    assert!(ForegroundFrame::new(source(4,&p,2,2),&p,&[1,1,1,2],&mut budget).is_err());
    assert!(ForegroundFrame::new(source(4,&p,2,2),&p[..3],&[1;4],&mut budget).is_err());Ok(())
}
#[test]
fn region_overflow_and_interruption_never_publish_a_prefix() -> Test {
    let m=model(3,3)?;let q=[200,100,100,100,200,100,100,100,200];let mask=[1;9];
    let mut budget=WorkBudget::new(10000);let f=ForegroundFrame::new(source(4,&q,3,3),&q,&mask,&mut budget)?;
    assert!(matches!(m.detect(&f,ForegroundPolicy{minimum_area:1,maximum_regions:2,..policy()},&mut budget),Err(ForegroundError::Limit)));
    assert!(matches!(m.detect(&f,policy(),&mut WorkBudget::new(0)),Err(ForegroundError::Geometry(GeometryError::BudgetExhausted))));
    let flag=AtomicBool::new(true);
    assert!(matches!(m.detect(&f,policy(),&mut WorkBudget::cancellable(10000,&flag)),Err(ForegroundError::Geometry(GeometryError::Cancelled))));
    assert_eq!(m.detect(&f,policy(),&mut WorkBudget::new(10000))?.changed_pixels(),3);Ok(())
}
#[test]
fn every_three_by_three_binary_mask_matches_an_independent_transitive_closure() -> Test {
    let m=model(3,3)?;
    for bits in 0_u16..512 {
        let p:Vec<_>=(0..9).map(|i|if bits&(1<<i)!=0 {200} else {100}).collect();
        let r=detect(&m,&p,&[1;9],3,3,ForegroundPolicy{minimum_area:1,..policy()})?;
        let mut connected=[[false;9];9];
        for i in 0_usize..9 {for j in 0_usize..9 {
            let adjacent=(i/3).abs_diff(j/3)+(i%3).abs_diff(j%3)<=1;
            connected[i][j]=bits&(1<<i)!=0 && bits&(1<<j)!=0 && adjacent;
        }}
        for k in 0..9 {for i in 0..9 {for j in 0..9 {connected[i][j]|=connected[i][k]&&connected[k][j];}}}
        for i in 0..9 {
            let expected=(0..9).find(|&j|connected[i][j]).map_or(0,|j|j as u32+1);
            assert_eq!(r.component_labels()[i],expected,"bits={bits}, pixel={i}");
        }
    }Ok(())
}
#[test]
fn exact_replay_is_stable_and_policy_mask_and_exposure_are_bound() -> Test {
    let m=model(2,2)?;let q=[150;4];let a=detect(&m,&q,&[1;4],2,2,policy())?;
    let b=detect(&m,&q,&[1;4],2,2,policy())?;assert_eq!(a.digest(),b.digest());
    let c=detect(&m,&q,&[1,1,1,0],2,2,policy())?;assert_ne!(a.digest(),c.digest());
    let d=detect(&m,&q,&[1;4],2,2,ForegroundPolicy{minimum_change:11,..policy()})?;
    assert_ne!(a.digest(),d.digest()); Ok(())
}

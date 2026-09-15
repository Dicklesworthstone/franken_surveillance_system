#![forbid(unsafe_code)]

use std::error::Error;
use std::sync::atomic::AtomicBool;
use fss_geometry::{Correspondence,FocalSampleOutcome,FocalScanOptions,GeometryBasis,GeometryError,
    PoseSolverOptions,WorkBudget,scan_camera_focal_length};

type Test=Result<(),Box<dyn Error>>;
fn points()->Vec<Correspondence>{
    (0..32).map(|i|{
        let n=i as f64+1.0;
        let world=[2.0*(n*0.7).sin(),1.5*(n*1.3).cos(),1.2*(n*0.31).sin()];
        let x=0.8*world[0]+0.6*world[2]+0.3;
        let y=world[1]-0.4;
        let z=-0.6*world[0]+0.8*world[2]+8.0;
        Correspondence{landmark:i+1,physical_group:i+1,world,
            pixel:[800.0*x/z+960.0,820.0*y/z+540.0]}
    }).collect()
}
fn options()->FocalScanOptions{
    FocalScanOptions{minimum_fx_px:400.0,maximum_fx_px:1600.0,y_over_x:820.0/800.0,
        principal_point:[960.0,540.0],samples:33,
        pose:PoseSolverOptions{ransac_trials:0,..PoseSolverOptions::default()}}
}

#[test]
fn scan_preserves_all_samples_and_contains_true_focal_solution()->Test{
    let scan=scan_camera_focal_length(GeometryBasis::new(1,1)?,[1920,1080],&points(),options(),&mut WorkBudget::new(500_000_000))?;
    assert_eq!(scan.samples().len(),33);
    assert!(scan.successful_samples()>0);
    let midpoint=&scan.samples()[16];
    assert!((midpoint.intrinsics().focal_lengths()[0]-800.0).abs()<1e-9);
    let FocalSampleOutcome::Candidates(search)=midpoint.outcome() else{return Err("true focal sample failed".into());};
    assert_eq!(search.candidates()[0].inlier_landmarks().len(),32);
    assert!(search.candidates()[0].rms_px()<1e-5);
    assert!(scan.admissible_candidates(30,0.01)?.contains(&(16,0)));
    Ok(())
}

#[test]
fn scan_does_not_silently_select_or_drop_geometric_failures()->Test{
    let mut opt=options(); opt.samples=9;
    let scan=scan_camera_focal_length(GeometryBasis::new(1,1)?,[1920,1080],&points(),opt,&mut WorkBudget::new(200_000_000))?;
    assert_eq!(scan.samples().len(),9);
    for sample in scan.samples(){
        match sample.outcome(){
            FocalSampleOutcome::Candidates(search)=>assert!(!search.candidates().is_empty()),
            FocalSampleOutcome::GeometricFailure(error)=>assert!(!matches!(error,GeometryError::Cancelled|GeometryError::BudgetExhausted|GeometryError::LimitExceeded)),
        }
    }
    Ok(())
}

#[test]
fn invalid_family_and_control_failures_refuse_partial_scans()->Test{
    let mut bad=options(); bad.samples=2;
    assert!(matches!(scan_camera_focal_length(GeometryBasis::new(1,1)?,[1920,1080],&points(),bad,&mut WorkBudget::new(100_000)),Err(GeometryError::InvalidSolverOptions)));
    let flag=AtomicBool::new(true);
    assert!(matches!(scan_camera_focal_length(GeometryBasis::new(1,1)?,[1920,1080],&points(),options(),&mut WorkBudget::cancellable(500_000_000,&flag)),Err(GeometryError::Cancelled)));
    assert!(matches!(scan_camera_focal_length(GeometryBasis::new(1,1)?,[1920,1080],&points(),options(),&mut WorkBudget::new(1)),Err(GeometryError::BudgetExhausted)));
    Ok(())
}

#![forbid(unsafe_code)]
//! Bounded known-principal-point focal scan over the existing adaptive pose solver.
//! Every sampled outcome is preserved; no focal value becomes authority by ranking alone.

use super::{Correspondence, PoseSearch, PoseSolverOptions, PoseValidation};
use super::planar::estimate_camera_pose_adaptive;
use crate::{GeometryBasis, GeometryError, PinholeIntrinsics, WorkBudget};

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FocalScanOptions {
    pub minimum_fx_px: f64, pub maximum_fx_px: f64, pub y_over_x: f64,
    pub principal_point: [f64;2], pub samples: usize, pub pose: PoseSolverOptions,
}
impl FocalScanOptions {
    fn validate(self, dimensions:[u32;2])->Result<(),GeometryError>{
        if dimensions[0]==0 || dimensions[1]==0 || self.samples<3 || self.samples>129
            || !self.minimum_fx_px.is_finite() || !self.maximum_fx_px.is_finite()
            || self.minimum_fx_px<1e-6 || self.maximum_fx_px<=self.minimum_fx_px || self.maximum_fx_px>1e9
            || !self.y_over_x.is_finite() || !(0.05..=20.0).contains(&self.y_over_x)
            || self.principal_point.iter().any(|v|!v.is_finite() || v.abs()>1e9) { return Err(GeometryError::InvalidSolverOptions); }
        Ok(())
    }
}

#[derive(Debug)]
pub enum FocalSampleOutcome { Candidates(PoseSearch), GeometricFailure(GeometryError) }
#[derive(Debug)]
pub struct FocalSample { intrinsics:PinholeIntrinsics, outcome:FocalSampleOutcome }
impl FocalSample { pub fn intrinsics(&self)->PinholeIntrinsics{self.intrinsics} pub fn outcome(&self)->&FocalSampleOutcome{&self.outcome} }

#[derive(Clone, Debug, PartialEq)]
pub struct FocalCandidateValidation { pub sample:usize, pub candidate:usize, pub validation:PoseValidation }
#[derive(Debug)]
pub struct FocalValidationSet<'a> {
    scan:&'a FocalPoseScan,
    reports:Vec<FocalCandidateValidation>,
    passing:Vec<(usize,usize)>,
}
impl<'a> FocalValidationSet<'a> {
    pub fn scan(&self)->&'a FocalPoseScan{self.scan}
    pub fn reports(&self)->&[FocalCandidateValidation]{&self.reports}
    pub fn passing_candidates(&self)->&[(usize,usize)]{&self.passing}
    pub fn unique_passing_candidate(&self)->Option<(usize,usize)>{match self.passing.as_slice(){&[(index,candidate)]=>Some((index,candidate)),_=>None}}
}

#[derive(Debug)]
pub struct FocalPoseScan {
    basis:GeometryBasis, dimensions:[u32;2], options:FocalScanOptions,
    samples:Vec<FocalSample>, work_units:u64,
}
impl FocalPoseScan {
    pub fn basis(&self)->GeometryBasis{self.basis}
    pub fn dimensions(&self)->[u32;2]{self.dimensions}
    pub fn options(&self)->FocalScanOptions{self.options}
    pub fn samples(&self)->&[FocalSample]{&self.samples}
    pub fn work_units(&self)->u64{self.work_units}
    pub fn successful_samples(&self)->usize{self.samples.iter().filter(|s|matches!(&s.outcome,FocalSampleOutcome::Candidates(_))).count()}
    pub fn admissible_candidates(&self,minimum_inliers:usize,maximum_rms_px:f64)->Result<Vec<(usize,usize)>,GeometryError>{
        let mut output=Vec::new();
        if minimum_inliers==0 || !maximum_rms_px.is_finite() || maximum_rms_px<0.0{return Ok(output);}
        output.try_reserve_exact(self.samples.len().saturating_mul(8)).map_err(|_|GeometryError::LimitExceeded)?;
        for (si,sample) in self.samples.iter().enumerate(){if let FocalSampleOutcome::Candidates(search)=&sample.outcome{
            for (ci,candidate) in search.candidates().iter().enumerate(){if candidate.inlier_landmarks().len()>=minimum_inliers && candidate.rms_px()<=maximum_rms_px{output.push((si,ci));}}
        }}
        Ok(output)
    }
    pub fn validate_all_candidates<'a>(&'a self,basis:GeometryBasis,holdout:&[Correspondence],maximum_error_px:f64,
        budget:&mut WorkBudget<'_>)->Result<FocalValidationSet<'a>,GeometryError>{
        budget.charge(0)?; if basis!=self.basis{return Err(GeometryError::BasisMismatch);}
        let capacity=self.samples.len().saturating_mul(8);
        let mut reports=Vec::new();let mut passing=Vec::new();
        reports.try_reserve_exact(capacity).map_err(|_|GeometryError::LimitExceeded)?;
        passing.try_reserve_exact(capacity).map_err(|_|GeometryError::LimitExceeded)?;
        for (si,sample) in self.samples.iter().enumerate(){if let FocalSampleOutcome::Candidates(search)=&sample.outcome{
            for ci in 0..search.candidates().len(){
                let validation=search.validate_candidate(ci,basis,holdout,maximum_error_px,budget)?;
                if validation.passed{passing.push((si,ci));}
                reports.push(FocalCandidateValidation{sample:si,candidate:ci,validation});
            }
        }}
        budget.charge(0)?; Ok(FocalValidationSet{scan:self,reports,passing})
    }
}

#[cfg(test)]
mod unique_selection_tests {
    use super::*;

    fn scan()->FocalPoseScan{
        FocalPoseScan{basis:GeometryBasis::new(1,1).expect("basis"),dimensions:[1,1],
            options:FocalScanOptions{minimum_fx_px:1.,maximum_fx_px:2.,y_over_x:1.,
            principal_point:[0.,0.],samples:3,pose:PoseSolverOptions::default()},
            samples:Vec::new(),work_units:0}
    }
    fn set(scan:&FocalPoseScan,passing:Vec<(usize,usize)>)->FocalValidationSet<'_>{
        FocalValidationSet{scan,reports:Vec::new(),passing}
    }

    #[test]
    fn empty_passing_selection_is_none_without_panic(){
        let scan=scan();
        assert_eq!(set(&scan,Vec::new()).unique_passing_candidate(),None);
    }
    #[test]
    fn single_passing_selection_returns_indices(){
        let scan=scan();
        assert_eq!(set(&scan,vec![(2,1)]).unique_passing_candidate(),Some((2,1)));
    }
    #[test]
    fn multiple_passing_selection_stays_none(){
        let scan=scan();
        assert_eq!(set(&scan,vec![(2,1),(2,0)]).unique_passing_candidate(),None);
    }
}

pub fn scan_camera_focal_length(basis:GeometryBasis,dimensions:[u32;2],correspondences:&[Correspondence],
    options:FocalScanOptions,budget:&mut WorkBudget<'_>)->Result<FocalPoseScan,GeometryError>{
    budget.charge(0)?;options.validate(dimensions)?;let started=budget.used();
    let log_min=options.minimum_fx_px.ln();let log_max=options.maximum_fx_px.ln();
    let mut samples=Vec::new();samples.try_reserve_exact(options.samples).map_err(|_|GeometryError::LimitExceeded)?;
    for index in 0..options.samples{
        budget.charge(1)?;let fraction=index as f64/(options.samples-1) as f64;
        let fx=(log_min+(log_max-log_min)*fraction).exp();let fy=fx*options.y_over_x;
        let intrinsics=PinholeIntrinsics::new(dimensions[0],dimensions[1],fx,fy,options.principal_point[0],options.principal_point[1])?;
        let outcome=match estimate_camera_pose_adaptive(basis,intrinsics,correspondences,options.pose,budget){
            Ok(search)=>FocalSampleOutcome::Candidates(search),
            Err(error @ (GeometryError::Cancelled|GeometryError::BudgetExhausted|GeometryError::LimitExceeded))=>return Err(error),
            Err(error)=>FocalSampleOutcome::GeometricFailure(error),
        };
        samples.push(FocalSample{intrinsics,outcome});
    }
    budget.charge(0)?;Ok(FocalPoseScan{basis,dimensions,options,samples,work_units:budget.used()-started})
}

#![forbid(unsafe_code)]
//! Bounded known-principal-point focal scan over the existing adaptive pose solver.
//!
//! The scan preserves every sampled outcome. It does not silently choose one focal
//! length, claim identifiability, or convert image fit into a calibration certificate.

use super::{Correspondence, PoseSearch, PoseSolverOptions};
use super::planar::estimate_camera_pose_adaptive;
use crate::{GeometryBasis, GeometryError, PinholeIntrinsics, WorkBudget};

/// One-dimensional focal family: fx is scanned and fy = fx * y_over_x.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FocalScanOptions {
    pub minimum_fx_px: f64,
    pub maximum_fx_px: f64,
    pub y_over_x: f64,
    pub principal_point: [f64;2],
    /// Log-spaced complete sample count, 3..=129.
    pub samples: usize,
    /// Existing robust pose policy applied independently at every focal sample.
    pub pose: PoseSolverOptions,
}
impl FocalScanOptions {
    fn validate(self, dimensions:[u32;2])->Result<(),GeometryError>{
        if dimensions[0]==0 || dimensions[1]==0 || self.samples<3 || self.samples>129
            || !self.minimum_fx_px.is_finite() || !self.maximum_fx_px.is_finite()
            || self.minimum_fx_px<1e-6 || self.maximum_fx_px<=self.minimum_fx_px || self.maximum_fx_px>1e9
            || !self.y_over_x.is_finite() || !(0.05..=20.0).contains(&self.y_over_x)
            || self.principal_point.iter().any(|v|!v.is_finite() || v.abs()>1e9) {
            return Err(GeometryError::InvalidSolverOptions);
        }
        Ok(())
    }
}

/// Geometric result at one exact focal sample. Ordinary fit failures are retained;
/// resource/cancellation failures abort the whole scan so a partial profile is never
/// mistaken for a complete search.
#[derive(Debug)]
pub enum FocalSampleOutcome {
    Candidates(PoseSearch),
    GeometricFailure(GeometryError),
}
#[derive(Debug)]
pub struct FocalSample {
    intrinsics:PinholeIntrinsics,
    outcome:FocalSampleOutcome,
}
impl FocalSample {
    pub fn intrinsics(&self)->PinholeIntrinsics{self.intrinsics}
    pub fn outcome(&self)->&FocalSampleOutcome{&self.outcome}
}

/// Complete sampled focal profile. Sampling is evidence about this finite scan only.
#[derive(Debug)]
pub struct FocalPoseScan {
    basis:GeometryBasis,
    dimensions:[u32;2],
    options:FocalScanOptions,
    samples:Vec<FocalSample>,
    work_units:u64,
}
impl FocalPoseScan {
    pub fn basis(&self)->GeometryBasis{self.basis}
    pub fn dimensions(&self)->[u32;2]{self.dimensions}
    pub fn options(&self)->FocalScanOptions{self.options}
    pub fn samples(&self)->&[FocalSample]{&self.samples}
    pub fn work_units(&self)->u64{self.work_units}
    pub fn successful_samples(&self)->usize{
        self.samples.iter().filter(|s|matches!(s.outcome,FocalSampleOutcome::Candidates(_))).count()
    }
    /// Return every sampled (sample,candidate) meeting explicit caller thresholds.
    /// No normalization or best-only pruning occurs.
    pub fn admissible_candidates(&self,minimum_inliers:usize,maximum_rms_px:f64)->Vec<(usize,usize)> {
        let mut output=Vec::new();
        if minimum_inliers==0 || !maximum_rms_px.is_finite() || maximum_rms_px<0.0{return output;}
        for (sample_index,sample) in self.samples.iter().enumerate(){
            if let FocalSampleOutcome::Candidates(search)=&sample.outcome{
                for (candidate_index,candidate) in search.candidates().iter().enumerate(){
                    if candidate.inlier_landmarks().len()>=minimum_inliers && candidate.rms_px()<=maximum_rms_px{
                        output.push((sample_index,candidate_index));
                    }
                }
            }
        }
        output
    }
}

/// Evaluate a complete log-spaced focal profile using the adaptive nonplanar/planar
/// camera solver. Fixed principal point and focal aspect ratio are explicit assumptions.
pub fn scan_camera_focal_length(basis:GeometryBasis,dimensions:[u32;2],
    correspondences:&[Correspondence],options:FocalScanOptions,budget:&mut WorkBudget<'_>)
    ->Result<FocalPoseScan,GeometryError>{
    budget.charge(0)?;
    options.validate(dimensions)?;
    let started=budget.used();
    let log_min=options.minimum_fx_px.ln();
    let log_max=options.maximum_fx_px.ln();
    let mut samples=Vec::new();
    samples.try_reserve_exact(options.samples).map_err(|_|GeometryError::LimitExceeded)?;
    for index in 0..options.samples{
        budget.charge(1)?;
        let fraction=index as f64/(options.samples-1) as f64;
        let fx=(log_min+(log_max-log_min)*fraction).exp();
        let fy=fx*options.y_over_x;
        let intrinsics=PinholeIntrinsics::new(dimensions[0],dimensions[1],fx,fy,
            options.principal_point[0],options.principal_point[1])?;
        let outcome=match estimate_camera_pose_adaptive(basis,intrinsics,correspondences,options.pose,budget){
            Ok(search)=>FocalSampleOutcome::Candidates(search),
            Err(error @ (GeometryError::Cancelled|GeometryError::BudgetExhausted|GeometryError::LimitExceeded))=>return Err(error),
            Err(error)=>FocalSampleOutcome::GeometricFailure(error),
        };
        samples.push(FocalSample{intrinsics,outcome});
    }
    budget.charge(0)?;
    Ok(FocalPoseScan{basis,dimensions,options,samples,work_units:budget.used()-started})
}

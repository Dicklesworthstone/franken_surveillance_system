#![forbid(unsafe_code)]
//! Joint focal-length and one-coefficient radial-distortion localization over matched raw pixels.
//!
//! Descriptors are matched once in the original image grid. Every sampled lens candidate
//! independently undistorts those exact image observations and invokes the existing adaptive
//! planar/nonplanar pose solver. All sampled outcomes are retained; no best-only calibration.

use fss_geometry::{Correspondence,GeometryError,PinholeIntrinsics,PoseSearch,PoseSolverOptions,PoseValidation,WorkBudget,estimate_camera_pose};
use crate::PropertyTwin;
use crate::localization::{FeatureFrame,LocalizationAtlas,LocalizationError,MatchOptions,MatchReport};
use crate::localization::native::{ExtractedFrame,ExtractionOptions,GrayImage,extract_gray};

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RadialFocalScanOptions {
    pub minimum_fx_px:f64,pub maximum_fx_px:f64,pub focal_samples:usize,pub y_over_x:f64,
    pub principal_point:[f64;2],pub minimum_k1:f64,pub maximum_k1:f64,pub k1_samples:usize,
    pub maximum_undistorted_radius:f64,pub pose:PoseSolverOptions,
}
impl RadialFocalScanOptions {
    fn validate(self,dimensions:[u32;2])->Result<(),LocalizationError>{
        let product=self.focal_samples.checked_mul(self.k1_samples).ok_or(LocalizationError::Limit)?;
        if dimensions.iter().any(|n|*n==0) || !(3..=65).contains(&self.focal_samples)
            || !(1..=33).contains(&self.k1_samples) || product>1024
            || !self.minimum_fx_px.is_finite() || !self.maximum_fx_px.is_finite()
            || self.minimum_fx_px<1e-6 || self.maximum_fx_px<=self.minimum_fx_px || self.maximum_fx_px>1e9
            || !self.y_over_x.is_finite() || !(0.05..=20.0).contains(&self.y_over_x)
            || self.principal_point.iter().any(|v|!v.is_finite()||v.abs()>1e9)
            || !self.minimum_k1.is_finite() || !self.maximum_k1.is_finite()
            || self.minimum_k1>self.maximum_k1 || self.minimum_k1.abs()>10.0 || self.maximum_k1.abs()>10.0
            || !self.maximum_undistorted_radius.is_finite() || !(1e-3..=64.0).contains(&self.maximum_undistorted_radius){return Err(LocalizationError::InvalidInput);}
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RadialLensFailure { NonInvertible, ObservationOutsideAdmittedDomain }
#[derive(Debug)]
pub enum RadialSampleOutcome { Candidates(PoseSearch), LensFailure(RadialLensFailure), GeometricFailure(GeometryError) }
#[derive(Debug)]
pub struct RadialFocalSample { pub focal_index:usize,pub k1_index:usize,pub k1:f64,pub intrinsics:PinholeIntrinsics,pub outcome:RadialSampleOutcome }
#[derive(Debug)]
pub struct RadialFocalScan { pub basis:fss_geometry::GeometryBasis,pub dimensions:[u32;2],pub options:RadialFocalScanOptions,pub samples:Vec<RadialFocalSample>,pub work_units:u64 }

#[derive(Clone, Debug, PartialEq)]
pub struct RadialCandidateValidation { pub sample:usize,pub candidate:usize,pub validation:PoseValidation }
#[derive(Debug)]
pub struct RadialValidationSet<'a> { scan:&'a RadialFocalScan,reports:Vec<RadialCandidateValidation>,passing:Vec<(usize,usize)> }
impl<'a> RadialValidationSet<'a> {
    pub fn scan(&self)->&'a RadialFocalScan{self.scan}
    pub fn reports(&self)->&[RadialCandidateValidation]{&self.reports}
    pub fn passing_candidates(&self)->&[(usize,usize)]{&self.passing}
    pub fn unique_passing_candidate(&self)->Option<(usize,usize)>{(self.passing.len()==1).then_some(self.passing[0])}
}

impl RadialFocalScan {
    pub fn validate_all_candidates<'a>(&'a self,holdout_raw:&[Correspondence],maximum_error_px:f64,
        budget:&mut WorkBudget<'_>)->Result<RadialValidationSet<'a>,LocalizationError>{
        budget.charge(0)?;let mut reports=Vec::new();let mut passing=Vec::new();
        let capacity=self.samples.len().saturating_mul(8);
        reports.try_reserve_exact(capacity).map_err(|_|LocalizationError::Limit)?;
        passing.try_reserve_exact(capacity).map_err(|_|LocalizationError::Limit)?;
        for (sample_index,sample) in self.samples.iter().enumerate(){
            let RadialSampleOutcome::Candidates(search)=&sample.outcome else{continue;};
            let adjusted=match undistort_correspondences(holdout_raw,sample.intrinsics,sample.k1,self.options.maximum_undistorted_radius,budget){
                Ok(v)=>v,Err(UndistortError::Lens(_))=>continue,Err(UndistortError::Geometry(e))=>return Err(e.into()),Err(UndistortError::Limit)=>return Err(LocalizationError::Limit)};
            for candidate in 0..search.candidates().len(){
                let validation=search.validate_candidate(candidate,self.basis,&adjusted,maximum_error_px,budget)?;
                if validation.passed{passing.push((sample_index,candidate));}
                reports.push(RadialCandidateValidation{sample:sample_index,candidate,validation});
            }
        }
        budget.charge(0)?;Ok(RadialValidationSet{scan:self,reports,passing})
    }
}

#[derive(Debug)]
pub enum RadialLocalizationOutcome { InsufficientMatches{found:usize,required:usize}, Scan(RadialFocalScan) }
#[derive(Debug)]
pub struct RadialLocalization { pub matches:MatchReport,pub outcome:RadialLocalizationOutcome }
#[derive(Debug)]
pub struct GrayRadialLocalization { pub extraction:ExtractedFrame,pub localization:RadialLocalization }

pub fn localize_radial_focal_scan(atlas:&LocalizationAtlas,twin:&PropertyTwin,query:&FeatureFrame,
    matching:MatchOptions,options:RadialFocalScanOptions,budget:&mut WorkBudget<'_>)->Result<RadialLocalization,LocalizationError>{
    budget.charge(0)?;options.validate(query.identity().dimensions)?;
    if atlas.references().iter().any(|r|r.frame.identity().exposure==query.identity().exposure){return Err(LocalizationError::ReferenceExposure);}
    let matches=atlas.match_frame(twin,query,matching,budget)?;let required=6.max(options.pose.minimum_inliers);
    let outcome=if matches.correspondences.len()<required{RadialLocalizationOutcome::InsufficientMatches{found:matches.correspondences.len(),required}}
    else{RadialLocalizationOutcome::Scan(scan_radial_focal(twin.basis(),query.identity().dimensions,&matches.correspondences,options,budget)?)};
    budget.charge(0)?;Ok(RadialLocalization{matches,outcome})
}

pub fn localize_gray_radial_focal_scan(atlas:&LocalizationAtlas,twin:&PropertyTwin,image:&GrayImage<'_>,
    extraction:ExtractionOptions,matching:MatchOptions,options:RadialFocalScanOptions,
    budget:&mut WorkBudget<'_>)->Result<GrayRadialLocalization,LocalizationError>{
    budget.charge(0)?;let extracted=extract_gray(image,extraction,budget)?;
    let localization=localize_radial_focal_scan(atlas,twin,&extracted.frame,matching,options,budget)?;
    budget.charge(0)?;Ok(GrayRadialLocalization{extraction:extracted,localization})
}

pub fn scan_radial_focal(basis:fss_geometry::GeometryBasis,dimensions:[u32;2],raw:&[Correspondence],
    options:RadialFocalScanOptions,budget:&mut WorkBudget<'_>)->Result<RadialFocalScan,LocalizationError>{
    budget.charge(0)?;options.validate(dimensions)?;let started=budget.used();
    let count=options.focal_samples*options.k1_samples;let mut samples=Vec::new();
    samples.try_reserve_exact(count).map_err(|_|LocalizationError::Limit)?;
    let l0=options.minimum_fx_px.ln();let l1=options.maximum_fx_px.ln();
    for fi in 0..options.focal_samples{
        let ft=fi as f64/(options.focal_samples-1) as f64;let fx=(l0+(l1-l0)*ft).exp();let fy=fx*options.y_over_x;
        let intrinsics=PinholeIntrinsics::new(dimensions[0],dimensions[1],fx,fy,options.principal_point[0],options.principal_point[1])?;
        for ki in 0..options.k1_samples{
            budget.charge(1)?;let kt=if options.k1_samples==1{0.0}else{ki as f64/(options.k1_samples-1) as f64};
            let k1=options.minimum_k1+(options.maximum_k1-options.minimum_k1)*kt;
            let outcome=match undistort_correspondences(raw,intrinsics,k1,options.maximum_undistorted_radius,budget){
                Err(UndistortError::Lens(reason))=>RadialSampleOutcome::LensFailure(reason),
                Err(UndistortError::Geometry(e))=>return Err(e.into()),
                Err(UndistortError::Limit)=>return Err(LocalizationError::Limit),
                Ok(points)=>match estimate_camera_pose(basis,intrinsics,&points,options.pose,budget){
                    Ok(search)=>RadialSampleOutcome::Candidates(search),
                    Err(e @ (GeometryError::Cancelled|GeometryError::BudgetExhausted|GeometryError::LimitExceeded))=>return Err(e.into()),
                    Err(e)=>RadialSampleOutcome::GeometricFailure(e),
                }
            };
            samples.push(RadialFocalSample{focal_index:fi,k1_index:ki,k1,intrinsics,outcome});
        }
    }
    budget.charge(0)?;Ok(RadialFocalScan{basis,dimensions,options,samples,work_units:budget.used()-started})
}

enum UndistortError { Lens(RadialLensFailure), Geometry(GeometryError), Limit }
fn undistort_correspondences(raw:&[Correspondence],intrinsics:PinholeIntrinsics,k1:f64,max_radius:f64,
    budget:&mut WorkBudget<'_>)->Result<Vec<Correspondence>,UndistortError>{
    if !k1.is_finite() || !max_radius.is_finite() || max_radius<=0.0{return Err(UndistortError::Lens(RadialLensFailure::NonInvertible));}
    let r2=max_radius*max_radius;
    if 1.0+k1*r2<=1e-8 || 1.0+3.0*k1*r2<=1e-8{return Err(UndistortError::Lens(RadialLensFailure::NonInvertible));}
    let mut output=Vec::new();output.try_reserve_exact(raw.len()).map_err(|_|UndistortError::Limit)?;
    let [fx,fy]=intrinsics.focal_lengths();let [cx,cy]=intrinsics.principal_point();let maximum_distorted=max_radius*(1.0+k1*r2);
    for point in raw{
        budget.charge(64).map_err(UndistortError::Geometry)?;
        let xd=(point.pixel[0]-cx)/fx;let yd=(point.pixel[1]-cy)/fy;let rd=xd.hypot(yd);
        if !rd.is_finite() || rd>maximum_distorted+1e-12{return Err(UndistortError::Lens(RadialLensFailure::ObservationOutsideAdmittedDomain));}
        let ru=if rd<=1e-15{0.0}else if k1==0.0{rd}else{
            let mut lo=0.0;let mut hi=max_radius;
            for _ in 0..48{let mid=(lo+hi)*0.5;let value=mid*(1.0+k1*mid*mid);if value<rd{lo=mid}else{hi=mid}}
            (lo+hi)*0.5
        };
        let scale=if rd<=1e-15{1.0}else{ru/rd};let pixel=[fx*xd*scale+cx,fy*yd*scale+cy];
        if !intrinsics.contains(pixel){return Err(UndistortError::Lens(RadialLensFailure::ObservationOutsideAdmittedDomain));}
        output.push(Correspondence{pixel,..*point});
    }
    Ok(output)
}

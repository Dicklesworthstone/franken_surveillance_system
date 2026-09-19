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

/// Tuning grid for the joint focal-length and radial-distortion scan, validated by [`RadialFocalScanOptions::validate`].
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RadialFocalScanOptions {
    /// Lowest horizontal focal length sampled, in pixels (log-spaced).
    pub minimum_fx_px:f64,
    /// Highest horizontal focal length sampled, in pixels (log-spaced).
    pub maximum_fx_px:f64,
    /// Number of focal-length samples on the logarithmic grid (3..=65).
    pub focal_samples:usize,
    /// Fixed vertical/horizontal focal-length ratio applied to every sample (0.05..=20.0).
    pub y_over_x:f64,
    /// Principal point shared by all sampled intrinsics, in pixels.
    pub principal_point:[f64;2],
    /// Lowest first-order radial-distortion coefficient sampled (|k1| <= 10).
    pub minimum_k1:f64,
    /// Highest first-order radial-distortion coefficient sampled (|k1| <= 10).
    pub maximum_k1:f64,
    /// Number of distortion coefficients sampled on a linear grid (1..=33).
    pub k1_samples:usize,
    /// Largest undistorted normalized radius admitted by the lens model, in pixels (1e-3..=64.0).
    pub maximum_undistorted_radius:f64,
    /// Adaptive solver configuration handed to [`estimate_camera_pose`].
    pub pose:PoseSolverOptions,
}
impl RadialFocalScanOptions {
    fn validate(self,dimensions:[u32;2])->Result<(),LocalizationError>{
        let product=self.focal_samples.checked_mul(self.k1_samples).ok_or(LocalizationError::Limit)?;
        if dimensions.contains(&0) || !(3..=65).contains(&self.focal_samples)
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

/// Failure modes specific to the radial lens model, independent of the geometric pose solver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RadialLensFailure {
    /// The distortion polynomial is not invertible over the admitted radius (division collapses).
    NonInvertible,
    /// A raw observation undistorts outside the sensor or the admitted maximum radius.
    ObservationOutsideAdmittedDomain,
}
/// Per-lens-candidate outcome retained from the scan; failures are kept instead of aborting.
#[derive(Debug)]
pub enum RadialSampleOutcome {
    /// The adaptive pose solver produced candidate poses for this lens sample.
    Candidates(Box<PoseSearch>),
    /// The lens model rejected this sample for the given [`RadialLensFailure`].
    LensFailure(RadialLensFailure),
    /// The pose solver failed with a non-fatal geometry error.
    GeometricFailure(GeometryError),
}
/// One point on the (focal length, k1) grid with its undistorted pose result.
#[derive(Debug)]
pub struct RadialFocalSample {
    /// Index of this sample along the logarithmic focal-length axis.
    pub focal_index:usize,
    /// Index of this sample along the linear k1 axis.
    pub k1_index:usize,
    /// First-order radial-distortion coefficient at `k1_index`.
    pub k1:f64,
    /// Full intrinsics (focal lengths, principal point) at `focal_index`.
    pub intrinsics:PinholeIntrinsics,
    /// Solver outcome for this lens candidate.
    pub outcome:RadialSampleOutcome,
}
/// Complete grid of lens samples over the matched correspondences.
#[derive(Debug)]
pub struct RadialFocalScan {
    /// Geometric basis (planar/nonplanar) shared by all pose searches.
    pub basis:fss_geometry::GeometryBasis,
    /// Image dimensions in pixels the intrinsics were built for.
    pub dimensions:[u32;2],
    /// The option grid that produced this scan.
    pub options:RadialFocalScanOptions,
    /// `focal_samples * k1_samples` retained samples, row-major by focal index.
    pub samples:Vec<RadialFocalSample>,
    /// Work units charged to the budget while producing this scan.
    pub work_units:u64,
}

/// Holdout validation verdict for one lens candidate from [`RadialFocalScan::validate_all_candidates`].
#[derive(Clone, Debug, PartialEq)]
pub struct RadialCandidateValidation {
    /// Index into [`RadialFocalScan::samples`].
    pub sample:usize,
    /// Pose-candidate index within that sample's [`PoseSearch`].
    pub candidate:usize,
    /// Reprojection verdict of the candidate on the holdout correspondences.
    pub validation:PoseValidation,
}
/// Read-only holdout validation of every candidate pose from a completed scan.
#[derive(Debug)]
pub struct RadialValidationSet<'a> {
    /// The scan this validation was computed against.
    scan:&'a RadialFocalScan,
    /// One verdict per (sample, candidate) pair, in scan order.
    reports:Vec<RadialCandidateValidation>,
    /// Indices of candidates whose validation passed, in scan order.
    passing:Vec<(usize,usize)>,
}
impl<'a> RadialValidationSet<'a> {
    /// The scan these validation reports were computed against.
    pub fn scan(&self)->&'a RadialFocalScan{self.scan}
    /// Verdicts for every validated candidate, in scan order.
    pub fn reports(&self)->&[RadialCandidateValidation]{&self.reports}
    /// (sample, candidate) indices of every candidate that passed holdout validation.
    pub fn passing_candidates(&self)->&[(usize,usize)]{&self.passing}
    /// The single passing candidate, or `None` if zero or multiple candidates passed.
    pub fn unique_passing_candidate(&self)->Option<(usize,usize)>{(self.passing.len()==1).then_some(self.passing[0])}
}

impl RadialFocalScan {
    /// Re-undistorts holdout correspondences under every sampled lens and validates each
    /// candidate pose against `maximum_error_px`; returns per-candidate verdicts.
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

/// Terminal result of a radial scan request: either too few matches, or the full lens scan.
#[derive(Debug)]
pub enum RadialLocalizationOutcome {
    /// Only `found` matches were available where `required` were needed.
    InsufficientMatches{
        /// Correspondence count actually matched for the query image.
        found:usize,
        /// Minimum support count the joint scan demanded.
        required:usize,
    },
    /// Enough matches existed; the complete joint focal/k1 scan.
    Scan(RadialFocalScan),
}
/// Match statistics plus the radial-localization outcome.
#[derive(Debug)]
pub struct RadialLocalization {
    /// Descriptor match report consumed for this localization.
    pub matches:MatchReport,
    /// Whether the scan ran, or matches were insufficient.
    pub outcome:RadialLocalizationOutcome,
}
/// Radial localization over a luminance frame that was extracted in-process.
#[derive(Debug)]
pub struct GrayRadialLocalization {
    /// Grayscale extraction result (frame plus timing/work metadata).
    pub extraction:ExtractedFrame,
    /// Localization computed from the extracted frame.
    pub localization:RadialLocalization,
}

/// Matches `query` against the atlas, then scans joint focal-length and k1 candidates
/// over the matched raw-pixel correspondences; `required` = max(6, `options.pose.minimum_inliers`).
pub fn localize_radial_focal_scan(atlas:&LocalizationAtlas,twin:&PropertyTwin,query:&FeatureFrame,
    matching:MatchOptions,options:RadialFocalScanOptions,budget:&mut WorkBudget<'_>)->Result<RadialLocalization,LocalizationError>{
    budget.charge(0)?;options.validate(query.identity().dimensions)?;
    if atlas.references().iter().any(|r|r.frame.identity().exposure==query.identity().exposure){return Err(LocalizationError::ReferenceExposure);}
    let matches=atlas.match_frame(twin,query,matching,budget)?;let required=6.max(options.pose.minimum_inliers);
    let outcome=if matches.correspondences.len()<required{RadialLocalizationOutcome::InsufficientMatches{found:matches.correspondences.len(),required}}
    else{RadialLocalizationOutcome::Scan(scan_radial_focal(twin.basis(),query.identity().dimensions,&matches.correspondences,options,budget)?)};
    budget.charge(0)?;Ok(RadialLocalization{matches,outcome})
}

/// Extracts the grayscale frame, then runs [`localize_radial_focal_scan`] on it.
pub fn localize_gray_radial_focal_scan(atlas:&LocalizationAtlas,twin:&PropertyTwin,image:&GrayImage<'_>,
    extraction:ExtractionOptions,matching:MatchOptions,options:RadialFocalScanOptions,
    budget:&mut WorkBudget<'_>)->Result<GrayRadialLocalization,LocalizationError>{
    budget.charge(0)?;let extracted=extract_gray(image,extraction,budget)?;
    let localization=localize_radial_focal_scan(atlas,twin,&extracted.frame,matching,options,budget)?;
    budget.charge(0)?;Ok(GrayRadialLocalization{extraction:extracted,localization})
}

/// Builds the `focal_samples * k1_samples` grid: log-spaced focal lengths, linear k1,
/// undistorting `raw` per candidate before invoking the adaptive pose solver.
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
                    Ok(search)=>RadialSampleOutcome::Candidates(Box::new(search)),
                    Err(e @ (GeometryError::Cancelled|GeometryError::BudgetExhausted|GeometryError::LimitExceeded))=>return Err(e.into()),
                    Err(e)=>RadialSampleOutcome::GeometricFailure(e),
                }
            };
            samples.push(RadialFocalSample{focal_index:fi,k1_index:ki,k1,intrinsics,outcome});
        }
    }
    budget.charge(0)?;Ok(RadialFocalScan{basis,dimensions,options,samples,work_units:budget.used()-started})
}

/// Errors from the per-point undistortion pass; `Limit` distinguishes allocation/budget exhaustion.
enum UndistortError { Lens(RadialLensFailure), Geometry(GeometryError), Limit }
/// Undistorts raw-pixel correspondences through the k1 lens model by binary search on the
/// inverse radial polynomial; rejects points falling outside the admitted domain.
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

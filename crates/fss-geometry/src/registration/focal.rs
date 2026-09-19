#![forbid(unsafe_code)]
//! Bounded known-principal-point focal scan over the existing adaptive pose solver.
//! Every sampled outcome is preserved; no focal value becomes authority by ranking alone.

use super::planar::estimate_camera_pose_adaptive;
use super::{Correspondence, PoseSearch, PoseSolverOptions, PoseValidation};
use crate::{GeometryBasis, GeometryError, PinholeIntrinsics, WorkBudget};

/// Bounds and sampling plan for a focal-length scan at a fixed principal point.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FocalScanOptions {
    /// Lowest horizontal focal length scanned, in pixels; finite and at least 1e-6.
    pub minimum_fx_px: f64,
    /// Highest horizontal focal length scanned, in pixels; strictly greater than `minimum_fx_px` and at most 1e9.
    pub maximum_fx_px: f64,
    /// Fixed vertical-to-horizontal focal ratio `fy / fx`, dimensionless, within `0.05..=20.0`.
    pub y_over_x: f64,
    /// Principal point `(cx, cy)` in pixels shared by every sample; components finite with magnitude at most 1e9.
    pub principal_point: [f64; 2],
    /// Number of logarithmically spaced focal lengths probed between the bounds; between 3 and 129 inclusive.
    pub samples: usize,
    /// Pose-solver configuration (RANSAC trials, refinement, inlier thresholds, seed) applied identically to every sample.
    pub pose: PoseSolverOptions,
}
impl FocalScanOptions {
    fn validate(self, dimensions: [u32; 2]) -> Result<(), GeometryError> {
        if dimensions[0] == 0
            || dimensions[1] == 0
            || self.samples < 3
            || self.samples > 129
            || !self.minimum_fx_px.is_finite()
            || !self.maximum_fx_px.is_finite()
            || self.minimum_fx_px < 1e-6
            || self.maximum_fx_px <= self.minimum_fx_px
            || self.maximum_fx_px > 1e9
            || !self.y_over_x.is_finite()
            || !(0.05..=20.0).contains(&self.y_over_x)
            || self
                .principal_point
                .iter()
                .any(|v| !v.is_finite() || v.abs() > 1e9)
        {
            return Err(GeometryError::InvalidSolverOptions);
        }
        Ok(())
    }
}

/// How the adaptive pose solve ended for one sampled focal length; control errors abort the scan instead.
#[derive(Debug)]
pub enum FocalSampleOutcome {
    /// The solve succeeded: its ranked candidate set, boxed to keep the enum small.
    Candidates(Box<PoseSearch>),
    /// The solve failed with a non-control geometry error; the sample is preserved and the scan continues.
    GeometricFailure(GeometryError),
}
/// One focal-length probe: the intrinsics used and the outcome the adaptive solver produced.
#[derive(Debug)]
pub struct FocalSample {
    intrinsics: PinholeIntrinsics,
    outcome: FocalSampleOutcome,
}
impl FocalSample {
    /// Intrinsics used for this probe, including its logarithmically interpolated focal lengths in pixels.
    pub fn intrinsics(&self) -> PinholeIntrinsics {
        self.intrinsics
    }
    /// Solver outcome for this probe, distinguishing produced candidate sets from recorded geometric failures.
    pub fn outcome(&self) -> &FocalSampleOutcome {
        &self.outcome
    }
}

/// Hold-out validation verdict for one candidate of one scan sample, from `FocalPoseScan::validate_all_candidates`.
#[derive(Clone, Debug, PartialEq)]
pub struct FocalCandidateValidation {
    /// Index of the scan sample that produced the candidate, into `FocalPoseScan::samples`.
    pub sample: usize,
    /// Index of the candidate within that sample's ranked candidate list.
    pub candidate: usize,
    /// Hold-out verdict: `passed` flag plus RMS and largest reprojection errors in pixels.
    pub validation: PoseValidation,
}
/// Complete hold-out validation report over every candidate of every successful sample of a scan.
#[derive(Debug)]
pub struct FocalValidationSet<'a> {
    scan: &'a FocalPoseScan,
    reports: Vec<FocalCandidateValidation>,
    passing: Vec<(usize, usize)>,
}
impl<'a> FocalValidationSet<'a> {
    /// The scan whose candidates were validated.
    pub fn scan(&self) -> &'a FocalPoseScan {
        self.scan
    }
    /// One verdict per candidate per successful sample, ordered by sample index then candidate index.
    pub fn reports(&self) -> &[FocalCandidateValidation] {
        &self.reports
    }
    /// `(sample, candidate)` pairs whose hold-out validation passed, in `reports` order.
    pub fn passing_candidates(&self) -> &[(usize, usize)] {
        &self.passing
    }
    /// The single passing pair when exactly one candidate passed; `None` when none or several did.
    pub fn unique_passing_candidate(&self) -> Option<(usize, usize)> {
        match self.passing.as_slice() {
            &[(index, candidate)] => Some((index, candidate)),
            _ => None,
        }
    }
}

/// Result of a bounded focal-length scan: one preserved outcome per probe, never ranked across focal values.
#[derive(Debug)]
pub struct FocalPoseScan {
    basis: GeometryBasis,
    dimensions: [u32; 2],
    options: FocalScanOptions,
    samples: Vec<FocalSample>,
    work_units: u64,
}
impl FocalPoseScan {
    /// The geometry basis every sample was solved against.
    pub fn basis(&self) -> GeometryBasis {
        self.basis
    }
    /// Image dimensions `[width, height]` in pixels the sampled intrinsics were built for.
    pub fn dimensions(&self) -> [u32; 2] {
        self.dimensions
    }
    /// The options the scan ran with, copied back unchanged.
    pub fn options(&self) -> FocalScanOptions {
        self.options
    }
    /// Every sample in scan order, including samples whose solve failed.
    pub fn samples(&self) -> &[FocalSample] {
        &self.samples
    }
    /// Work units this scan charged to the budget.
    pub fn work_units(&self) -> u64 {
        self.work_units
    }
    /// Number of samples whose outcome is `FocalSampleOutcome::Candidates`.
    pub fn successful_samples(&self) -> usize {
        self.samples
            .iter()
            .filter(|s| matches!(&s.outcome, FocalSampleOutcome::Candidates(_)))
            .count()
    }
    /// `(sample, candidate)` pairs with at least `minimum_inliers` inliers and RMS error at most
    /// `maximum_rms_px`, ordered by sample then candidate; empty when either bound is degenerate
    /// (`minimum_inliers == 0`, or non-finite or negative `maximum_rms_px`).
    pub fn admissible_candidates(
        &self,
        minimum_inliers: usize,
        maximum_rms_px: f64,
    ) -> Result<Vec<(usize, usize)>, GeometryError> {
        let mut output = Vec::new();
        if minimum_inliers == 0 || !maximum_rms_px.is_finite() || maximum_rms_px < 0.0 {
            return Ok(output);
        }
        output
            .try_reserve_exact(self.samples.len().saturating_mul(8))
            .map_err(|_| GeometryError::LimitExceeded)?;
        for (si, sample) in self.samples.iter().enumerate() {
            if let FocalSampleOutcome::Candidates(search) = &sample.outcome {
                for (ci, candidate) in search.candidates().iter().enumerate() {
                    if candidate.inlier_landmarks().len() >= minimum_inliers
                        && candidate.rms_px() <= maximum_rms_px
                    {
                        output.push((si, ci));
                    }
                }
            }
        }
        Ok(output)
    }
    /// Re-validates every candidate of every successful sample against `holdout` correspondences
    /// with tolerance `maximum_error_px`, returning per-candidate verdicts plus the passing subset.
    /// Fails on basis mismatch; control errors (cancellation, budget exhaustion, limits) propagate.
    pub fn validate_all_candidates<'a>(
        &'a self,
        basis: GeometryBasis,
        holdout: &[Correspondence],
        maximum_error_px: f64,
        budget: &mut WorkBudget<'_>,
    ) -> Result<FocalValidationSet<'a>, GeometryError> {
        budget.charge(0)?;
        if basis != self.basis {
            return Err(GeometryError::BasisMismatch);
        }
        let capacity = self.samples.len().saturating_mul(8);
        let mut reports = Vec::new();
        let mut passing = Vec::new();
        reports
            .try_reserve_exact(capacity)
            .map_err(|_| GeometryError::LimitExceeded)?;
        passing
            .try_reserve_exact(capacity)
            .map_err(|_| GeometryError::LimitExceeded)?;
        for (si, sample) in self.samples.iter().enumerate() {
            if let FocalSampleOutcome::Candidates(search) = &sample.outcome {
                for ci in 0..search.candidates().len() {
                    let validation =
                        search.validate_candidate(ci, basis, holdout, maximum_error_px, budget)?;
                    if validation.passed {
                        passing.push((si, ci));
                    }
                    reports.push(FocalCandidateValidation {
                        sample: si,
                        candidate: ci,
                        validation,
                    });
                }
            }
        }
        budget.charge(0)?;
        Ok(FocalValidationSet {
            scan: self,
            reports,
            passing,
        })
    }
}

/// Scans logarithmically spaced horizontal focal lengths between the configured bounds at a fixed
/// principal point, solving the pose at each probe with the adaptive solver. Control failures
/// (cancellation, budget exhaustion, limit breach) abort the scan; any other per-probe solver
/// error is preserved as `FocalSampleOutcome::GeometricFailure` and scanning continues.
pub fn scan_camera_focal_length(
    basis: GeometryBasis,
    dimensions: [u32; 2],
    correspondences: &[Correspondence],
    options: FocalScanOptions,
    budget: &mut WorkBudget<'_>,
) -> Result<FocalPoseScan, GeometryError> {
    budget.charge(0)?;
    options.validate(dimensions)?;
    let started = budget.used();
    let log_min = options.minimum_fx_px.ln();
    let log_max = options.maximum_fx_px.ln();
    let mut samples = Vec::new();
    samples
        .try_reserve_exact(options.samples)
        .map_err(|_| GeometryError::LimitExceeded)?;
    for index in 0..options.samples {
        budget.charge(1)?;
        let fraction = index as f64 / (options.samples - 1) as f64;
        let fx = (log_min + (log_max - log_min) * fraction).exp();
        let fy = fx * options.y_over_x;
        let intrinsics = PinholeIntrinsics::new(
            dimensions[0],
            dimensions[1],
            fx,
            fy,
            options.principal_point[0],
            options.principal_point[1],
        )?;
        let outcome = match estimate_camera_pose_adaptive(
            basis,
            intrinsics,
            correspondences,
            options.pose,
            budget,
        ) {
            Ok(search) => FocalSampleOutcome::Candidates(Box::new(search)),
            Err(
                error @ (GeometryError::Cancelled
                | GeometryError::BudgetExhausted
                | GeometryError::LimitExceeded),
            ) => return Err(error),
            Err(error) => FocalSampleOutcome::GeometricFailure(error),
        };
        samples.push(FocalSample {
            intrinsics,
            outcome,
        });
    }
    budget.charge(0)?;
    Ok(FocalPoseScan {
        basis,
        dimensions,
        options,
        samples,
        work_units: budget.used() - started,
    })
}

#[cfg(test)]
mod unique_selection_tests {
    use super::*;

    fn scan() -> Result<FocalPoseScan, GeometryError> {
        Ok(FocalPoseScan {
            basis: GeometryBasis::new(1, 1)?,
            dimensions: [1, 1],
            options: FocalScanOptions {
                minimum_fx_px: 1.,
                maximum_fx_px: 2.,
                y_over_x: 1.,
                principal_point: [0., 0.],
                samples: 3,
                pose: PoseSolverOptions::default(),
            },
            samples: Vec::new(),
            work_units: 0,
        })
    }
    fn set(scan: &FocalPoseScan, passing: Vec<(usize, usize)>) -> FocalValidationSet<'_> {
        FocalValidationSet {
            scan,
            reports: Vec::new(),
            passing,
        }
    }

    #[test]
    fn empty_passing_selection_is_none_without_panic() -> Result<(), GeometryError> {
        let scan = scan()?;
        assert_eq!(set(&scan, Vec::new()).unique_passing_candidate(), None);
        Ok(())
    }
    #[test]
    fn single_passing_selection_returns_indices() -> Result<(), GeometryError> {
        let scan = scan()?;
        assert_eq!(
            set(&scan, vec![(2, 1)]).unique_passing_candidate(),
            Some((2, 1))
        );
        Ok(())
    }
    #[test]
    fn multiple_passing_selection_stays_none() -> Result<(), GeometryError> {
        let scan = scan()?;
        assert_eq!(
            set(&scan, vec![(2, 1), (2, 0)]).unique_passing_candidate(),
            None
        );
        Ok(())
    }
}

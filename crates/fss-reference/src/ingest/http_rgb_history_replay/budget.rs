#![forbid(unsafe_code)]
//! Whole-session allowances shared by every frame and retained after failure.

use super::{ReplayError, ReplayLimits};
use crate::ingest::model_import::ImportBudget;
use crate::ingest::rgb_detections::RgbDetectionBudget;
use crate::ingest::rgb_evidence::RgbEvidenceBudget;
use fss_codec_mjpeg::DecodeBudget;
use fss_geometry::WorkBudget;

/// Independent caller ceilings. No allowance is read from a stored recipe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplayAllowance {
    /// Total native cursor calls across all attempts using this budget.
    pub steps: u64,
    /// Total admitted numerical replay attempts, including failed attempts.
    pub inferences: u64,
    /// Original/history/archive verification and orchestration work.
    pub source: u64,
    /// Source envelope copying, hashing and framing work.
    pub copy: u64,
    /// Native graph/weight importer work.
    pub import: u64,
    /// Native HTTP and MIME work.
    pub framing: u64,
    /// Native JPEG decoder work.
    pub decode: u64,
    /// Complete detector-head projection work.
    pub detections: u64,
    /// Native tracking and zone work.
    pub temporal: u64,
    /// Sum of admitted per-attempt preprocessing and neural-operation ceilings.
    /// This is a conservative reservation, NOT measured or executed operations.
    pub numerical: u64,
}
impl Default for ReplayAllowance {
    fn default() -> Self {
        Self {
            steps: 1_000_000,
            inferences: 64,
            source: 10_000_000_000_000,
            copy: 100_000_000_000,
            import: 10_000_000_000,
            framing: 1_000_000_000,
            decode: 10_000_000_000,
            detections: 1_000_000_000,
            temporal: 1_000_000_000,
            numerical: 2_000_000_000_000,
        }
    }
}

/// Cumulative usage, including charged work from unsuccessful replay calls.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReplayUsage {
    /// Admitted native cursor calls, including terminal verification.
    pub steps: u64,
    /// Admitted numerical attempts, not necessarily successful model results.
    pub inferences: u64,
    /// Original, history and archive verification work.
    pub source: u64,
    /// Envelope work.
    pub copy: u64,
    /// Import work.
    pub import: u64,
    /// HTTP/MIME work.
    pub framing: u64,
    /// JPEG work.
    pub decode: u64,
    /// Detector projection work.
    pub detections: u64,
    /// Tracker/zone work.
    pub temporal: u64,
    /// Reserved preprocessing plus neural ceilings; not actual numerical operations.
    pub numerical_reserved: u64,
}

/// Caller-owned cumulative budgets. Constructing another budget is an explicit new allowance;
/// neither moving to another frame nor retrying a failed session replenishes this instance.
pub struct ReplayBudget {
    allowance: ReplayAllowance,
    steps: u64,
    inferences: u64,
    pub(super) source: WorkBudget<'static>,
    pub(super) copy: RgbEvidenceBudget,
    pub(super) import: ImportBudget,
    pub(super) framing: DecodeBudget<'static>,
    pub(super) decode: DecodeBudget<'static>,
    pub(super) detections: RgbDetectionBudget,
    pub(super) temporal: WorkBudget<'static>,
    numerical: WorkBudget<'static>,
}
impl ReplayBudget {
    /// Explicit deterministic allowances and per-call detector scratch, capped at 64 MiB.
    /// Zero work is valid and refuses the first operation needing that resource.
    pub fn new(allowance: ReplayAllowance, detection_scratch: usize) -> Result<Self, ReplayError> {
        if allowance.steps > 1_000_000
            || allowance.inferences > 4096
            || detection_scratch > 64 * 1024 * 1024
            || [
                allowance.source,
                allowance.copy,
                allowance.import,
                allowance.framing,
                allowance.decode,
                allowance.detections,
                allowance.temporal,
                allowance.numerical,
            ]
            .into_iter()
            .any(|n| n > 1_000_000_000_000_000)
        {
            return Err(ReplayError::Limit);
        }
        Ok(Self {
            allowance,
            steps: 0,
            inferences: 0,
            source: WorkBudget::new(allowance.source),
            copy: RgbEvidenceBudget::new(allowance.copy),
            import: ImportBudget::new(allowance.import),
            framing: DecodeBudget::new(allowance.framing),
            decode: DecodeBudget::new(allowance.decode),
            detections: RgbDetectionBudget::new(allowance.detections, detection_scratch),
            temporal: WorkBudget::new(allowance.temporal),
            numerical: WorkBudget::new(allowance.numerical),
        })
    }
    /// Complete original allowance, not inferred from remaining counters.
    pub fn allowance(&self) -> ReplayAllowance {
        self.allowance
    }
    /// Cumulative counters remain inspectable after every refusal.
    pub fn used(&self) -> ReplayUsage {
        ReplayUsage {
            steps: self.steps,
            inferences: self.inferences,
            source: self.source.used(),
            copy: self.copy.used(),
            import: self.import.used(),
            framing: self.framing.used(),
            decode: self.decode.used(),
            detections: self.detections.used(),
            temporal: self.temporal.used(),
            numerical_reserved: self.numerical.used(),
        }
    }
    pub(super) fn step(&mut self) -> Result<(), ReplayError> {
        if self.steps == self.allowance.steps {
            return Err(ReplayError::Limit);
        }
        self.steps += 1;
        Ok(())
    }
    pub(super) fn inference(&mut self, limits: ReplayLimits) -> Result<(), ReplayError> {
        if self.inferences == self.allowance.inferences {
            return Err(ReplayError::Limit);
        }
        let reservation = limits
            .execution
            .run
            .preprocess
            .max_macs
            .checked_add(limits.execution.run.execution.max_macs)
            .ok_or(ReplayError::Limit)?;
        // Charge BEFORE native work. An error cannot hide partial execution, and no refund is
        // inferred from missing native counters. Successful reports separately show actual work.
        self.numerical
            .charge(reservation)
            .map_err(ReplayError::Work)?;
        self.inferences += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inference_allowance_does_not_refill_between_attempts() -> Result<(), ReplayError> {
        let limits = ReplayLimits::default();
        let cost =
            limits.execution.run.preprocess.max_macs + limits.execution.run.execution.max_macs;
        let mut b = ReplayBudget::new(
            ReplayAllowance {
                inferences: 2,
                numerical: cost * 2,
                ..ReplayAllowance::default()
            },
            1024,
        )?;
        b.inference(limits)?;
        b.inference(limits)?;
        assert!(matches!(b.inference(limits), Err(ReplayError::Limit)));
        assert_eq!(b.used().inferences, 2);
        assert_eq!(b.used().numerical_reserved, 2 * cost);
        Ok(())
    }
    #[test]
    fn incomplete_reservation_runs_no_inference() -> Result<(), ReplayError> {
        let limits = ReplayLimits::default();
        let cost =
            limits.execution.run.preprocess.max_macs + limits.execution.run.execution.max_macs;
        let mut b = ReplayBudget::new(
            ReplayAllowance {
                numerical: cost - 1,
                ..ReplayAllowance::default()
            },
            1024,
        )?;
        assert!(b.inference(limits).is_err());
        assert_eq!(b.used().inferences, 0);
        assert_eq!(b.used().numerical_reserved, 0);
        Ok(())
    }
    #[test]
    fn zero_and_exhausted_step_allowances_fail_closed() -> Result<(), ReplayError> {
        let mut b = ReplayBudget::new(
            ReplayAllowance {
                steps: 1,
                ..ReplayAllowance::default()
            },
            1024,
        )?;
        b.step()?;
        assert!(matches!(b.step(), Err(ReplayError::Limit)));
        assert_eq!(b.used().steps, 1);
        let mut zero = ReplayBudget::new(
            ReplayAllowance {
                steps: 0,
                ..ReplayAllowance::default()
            },
            1024,
        )?;
        assert!(zero.step().is_err());
        Ok(())
    }
    #[test]
    fn overflowing_numerical_reservation_is_not_admitted() -> Result<(), ReplayError> {
        let mut limits = ReplayLimits::default();
        limits.execution.run.preprocess.max_macs = u64::MAX;
        limits.execution.run.execution.max_macs = 1;
        let mut b = ReplayBudget::new(ReplayAllowance::default(), 1024)?;
        assert!(matches!(b.inference(limits), Err(ReplayError::Limit)));
        assert_eq!(b.used(), ReplayUsage::default());
        Ok(())
    }
}

//! Sticky invalidation, historical rollback, and explicit fresh-sample recovery.

use super::{ClockOffsetSkewEstimator, ClockSyncEstimate, EstimatorState, TimeSyncSample};
use crate::ReferenceError;
use fss_core::{CaptureInterval, TimestampNs};

/// Earliest known invalidation fences history; latest observation fences fresh sampling.
/// This bounded record survives every rollback, including exhaustion of retained estimates.
#[derive(Clone, Debug)]
pub(super) struct ClockInvalidation {
    first_sample: TimeSyncSample,
    latest_reference: TimestampNs,
    highest_sequence: u64,
}

impl ClockOffsetSkewEstimator {
    /// Whether new calibration requires an explicit fresh sampling epoch.
    /// Historical rollback never clears this fence or renews a contradicted estimate.
    #[must_use]
    pub const fn requires_recalibration(&self) -> bool {
        self.invalidation.is_some()
    }

    /// Earliest retained invalidation observation, including after historical rollback.
    /// It is not part of the accepted fit samples and is never silently reused for recovery.
    #[must_use]
    pub fn invalidation_sample(&self) -> Option<&TimeSyncSample> {
        self.invalidation.as_ref().map(|fence| &fence.first_sample)
    }

    pub(super) fn ensure_calibration_current(&self) -> Result<(), ReferenceError> {
        if let Some(fence) = &self.invalidation {
            return Err(ReferenceError::ClockRecalibrationRequired {
                invalidated_at: fence.first_sample.reference_time,
            });
        }
        Ok(())
    }

    /// Start a separate uncalibrated instance with one explicitly supplied fresh observation.
    ///
    /// The reference timestamp and sample sequence must exceed every accepted observation
    /// and every explicitly recorded invalidation boundary. Sensor time may restart; no old
    /// sensor-clock continuity is asserted across this operation. The successor must gather
    /// the configured minimum samples and successfully fit before it has an active estimate.
    /// Its fit generations continue above those already issued by this instance.
    ///
    /// This method leaves this instance, its old fit samples, history and invalidation evidence
    /// unchanged, on success as well as refusal. The owner must retain that evidence separately.
    /// No stream generation, durable receipt, synchronization authority, or coverage is created.
    pub fn recalibrate_from(&self, first: TimeSyncSample) -> Result<Self, ReferenceError> {
        self.generation_counter
            .checked_add(1)
            .ok_or(ReferenceError::ArithmeticOverflow)?;
        let last = self.samples.last();
        let highest_sequence = last.map_or(0, |sample| sample.sequence).max(
            self.invalidation
                .as_ref()
                .map_or(0, |fence| fence.highest_sequence),
        );
        if first.sequence <= highest_sequence {
            return Err(ReferenceError::NonMonotonicSyncSequence {
                previous: highest_sequence,
                current: first.sequence,
            });
        }
        let latest_reference = last
            .map(|sample| sample.reference_time)
            .into_iter()
            .chain(
                self.invalidation
                    .as_ref()
                    .map(|fence| fence.latest_reference),
            )
            .max();
        if let Some(previous) = latest_reference
            && first.reference_time <= previous
        {
            return Err(ReferenceError::NonMonotonicSyncSamples {
                previous,
                current: first.reference_time,
            });
        }
        let mut successor = Self::new(self.config.clone())?;
        successor.generation_counter = self.generation_counter;
        successor.add_sample(first)?;
        Ok(successor)
    }

    /// Restore the immediately prior estimate for historical queries, if any remains valid.
    ///
    /// Every restored estimate keeps its original upper validity bound and is additionally
    /// clamped strictly before the earliest known invalidation. A contradiction at or before
    /// the first valid instant leaves no valid historical interval; it never invents a point.
    /// An empty history transitions to [`EstimatorState::Uncalibrated`].
    /// Invalidation remains sticky through all these transitions: rollback does not authorize
    /// adding samples or refitting an old clock epoch. Already issued external estimate copies
    /// are not mutated; their owners must honor the separately retained invalidation evidence.
    pub fn rollback(&mut self) -> Result<Option<ClockSyncEstimate>, ReferenceError> {
        let candidate = match &self.state {
            EstimatorState::Invalidated { prior_estimate, .. } => Some(prior_estimate.clone()),
            _ => self.prior_estimates.pop(),
        };
        let candidate = match (candidate, self.invalidation.as_ref()) {
            (Some(mut prior), Some(fence)) => {
                match fence.first_sample.reference_time.0.checked_sub(1) {
                    Some(cutoff) if cutoff >= prior.validity.earliest.0 => {
                        let latest = prior.validity.latest.0.min(cutoff);
                        prior.validity =
                            CaptureInterval::new(prior.validity.earliest, TimestampNs(latest))
                                .map_err(ReferenceError::Contract)?;
                        Some(prior)
                    }
                    _ => None,
                }
            }
            (candidate, _) => candidate,
        };
        if let Some(prior) = candidate {
            self.active_estimate = Some(prior.clone());
            self.state = EstimatorState::Synchronized(prior.clone());
            Ok(Some(prior))
        } else {
            self.active_estimate = None;
            self.state = EstimatorState::Uncalibrated;
            Ok(None)
        }
    }

    /// Invalidate an active calibration, or tighten the evidence of a previous invalidation.
    ///
    /// The earliest observation always fences historical validity, while the highest sequence
    /// and latest reference timestamp are retained independently for fresh-sampling admission.
    /// Calling this on a never-calibrated, unfenced instance has no effect.
    pub fn invalidate(&mut self, sample: TimeSyncSample, reason: impl Into<String>) {
        if self.active_estimate.is_none() && self.invalidation.is_none() {
            return;
        }
        if let Some(fence) = &mut self.invalidation {
            fence.latest_reference = fence.latest_reference.max(sample.reference_time);
            fence.highest_sequence = fence.highest_sequence.max(sample.sequence);
            if sample.reference_time < fence.first_sample.reference_time {
                fence.first_sample = sample.clone();
            }
        } else {
            self.invalidation = Some(ClockInvalidation {
                first_sample: sample.clone(),
                latest_reference: sample.reference_time,
                highest_sequence: sample.sequence,
            });
        }
        if let Some(active) = self.active_estimate.take() {
            self.state = EstimatorState::Invalidated {
                prior_estimate: active,
                contradicting_sample: sample,
                reason: reason.into(),
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EstimatorConfig;

    #[test]
    fn exhausted_generation_refuses_fresh_sampling_transactionally() -> Result<(), ReferenceError> {
        let mut estimator = ClockOffsetSkewEstimator::new(EstimatorConfig::default())?;
        estimator.generation_counter = u64::MAX;
        let sample = TimeSyncSample::new(1, TimestampNs(100), TimestampNs(1), 0)?;
        assert!(matches!(
            estimator.recalibrate_from(sample),
            Err(ReferenceError::ArithmeticOverflow)
        ));
        assert_eq!(estimator.generation_counter, u64::MAX);
        assert!(estimator.samples().is_empty());
        assert!(estimator.active_estimate().is_none());
        assert!(!estimator.requires_recalibration());
        Ok(())
    }
}

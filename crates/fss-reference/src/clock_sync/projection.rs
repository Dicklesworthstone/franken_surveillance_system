//! Conservative integer projections of the retained affine clock model.

use super::ClockSyncEstimate;
use crate::ReferenceError;
use fss_core::{CaptureInterval, TimestampNs};

const PPM: i128 = 1_000_000;

/// Return floor/ceil of the exact signed ratio without first forming `value * multiplier`.
/// Truncating division gives the whole and fractional products the same sign, so splitting
/// the product cannot hide overflow through cancellation. Every division has a positive divisor.
fn ratio_bounds(
    value: i128,
    multiplier: i128,
    divisor: i128,
) -> Result<(i128, i128), ReferenceError> {
    if divisor <= 0 {
        return Err(ReferenceError::ArithmeticOverflow);
    }
    let whole = (value / divisor)
        .checked_mul(multiplier)
        .ok_or(ReferenceError::ArithmeticOverflow)?;
    let fraction = (value % divisor)
        .checked_mul(multiplier)
        .ok_or(ReferenceError::ArithmeticOverflow)?;
    let truncated = whole
        .checked_add(fraction / divisor)
        .ok_or(ReferenceError::ArithmeticOverflow)?;
    let remainder = fraction % divisor;
    let lower = truncated
        .checked_sub(if remainder < 0 { 1 } else { 0 })
        .ok_or(ReferenceError::ArithmeticOverflow)?;
    let upper = truncated
        .checked_add(if remainder > 0 { 1 } else { 0 })
        .ok_or(ReferenceError::ArithmeticOverflow)?;
    Ok((lower, upper))
}

impl ClockSyncEstimate {
    /// Predicts sensor time with outward-rounded endpoints of the affine model.
    ///
    /// The reference instant must lie within the retained estimate's validity. Sample
    /// uncertainty and fit residuals are sensor-domain bounds; neither is discarded or
    /// saturated when composing the output interval. This projects the retained model,
    /// not a new synchronization or physical-coverage certificate.
    pub fn predict_sensor_interval(
        &self,
        ref_time: TimestampNs,
    ) -> Result<CaptureInterval, ReferenceError> {
        let uncertainty = self.projection_uncertainty()?;
        self.check_projection_time(ref_time)?;
        self.projection_rate()?;
        let delta = ref_time
            .0
            .checked_sub(self.reference_anchor.0)
            .ok_or(ReferenceError::ArithmeticOverflow)?;
        let (skew_lower, skew_upper) = ratio_bounds(delta, i128::from(self.skew_ppm), PPM)?;
        let base = ref_time
            .0
            .checked_add(i128::from(self.offset_ns))
            .ok_or(ReferenceError::ArithmeticOverflow)?;
        let earliest = base
            .checked_add(skew_lower)
            .and_then(|time| time.checked_sub(uncertainty))
            .ok_or(ReferenceError::ArithmeticOverflow)?;
        let latest = base
            .checked_add(skew_upper)
            .and_then(|time| time.checked_add(uncertainty))
            .ok_or(ReferenceError::ArithmeticOverflow)?;
        CaptureInterval::new(TimestampNs(earliest), TimestampNs(latest))
            .map_err(ReferenceError::Contract)
    }

    /// Predicts reference time by inverting both sensor-domain uncertainty endpoints.
    ///
    /// For sensor offset `d`, sensor uncertainty `u`, and positive clock rate `r` in ppm,
    /// the bounds are `anchor + floor((d-u)*1e6/r)` and
    /// `anchor + ceil((d+u)*1e6/r)`. In particular, a slow sensor widens uncertainty in
    /// reference time. Negative deltas round outward too, never toward zero.
    ///
    /// The exact nominal inverse must be within the estimate's validity; uncertainty
    /// may extend outside it, as for forward projection. No extrapolated nominal instant
    /// is admitted by rounding it back into the validity horizon.
    pub fn predict_reference_interval(
        &self,
        sensor_time: TimestampNs,
    ) -> Result<CaptureInterval, ReferenceError> {
        let uncertainty = self.projection_uncertainty()?;
        let rate = self.projection_rate()?;
        let delta = sensor_time
            .0
            .checked_sub(self.reference_anchor.0)
            .and_then(|time| time.checked_sub(i128::from(self.offset_ns)))
            .ok_or(ReferenceError::ArithmeticOverflow)?;
        let (nominal_lower, nominal_upper) = ratio_bounds(delta, PPM, rate)?;
        for nominal in [nominal_lower, nominal_upper] {
            let reference = self
                .reference_anchor
                .0
                .checked_add(nominal)
                .ok_or(ReferenceError::ArithmeticOverflow)?;
            self.check_projection_time(TimestampNs(reference))?;
        }
        let lower_delta = delta
            .checked_sub(uncertainty)
            .ok_or(ReferenceError::ArithmeticOverflow)?;
        let upper_delta = delta
            .checked_add(uncertainty)
            .ok_or(ReferenceError::ArithmeticOverflow)?;
        let (lower, _) = ratio_bounds(lower_delta, PPM, rate)?;
        let (_, upper) = ratio_bounds(upper_delta, PPM, rate)?;
        let earliest = self
            .reference_anchor
            .0
            .checked_add(lower)
            .ok_or(ReferenceError::ArithmeticOverflow)?;
        let latest = self
            .reference_anchor
            .0
            .checked_add(upper)
            .ok_or(ReferenceError::ArithmeticOverflow)?;
        CaptureInterval::new(TimestampNs(earliest), TimestampNs(latest))
            .map_err(ReferenceError::Contract)
    }

    fn projection_uncertainty(&self) -> Result<i128, ReferenceError> {
        let sample = self
            .sample_evidence
            .iter()
            .map(|sample| sample.uncertainty_ns)
            .max()
            .ok_or(ReferenceError::InsufficientSyncSamples {
                count: 0,
                minimum_required: 1,
            })?;
        // Two u64 bounds always fit in i128. Saturating their sum to u64::MAX would
        // silently narrow the interval precisely when the evidence is least certain.
        Ok((i128::from(sample) + i128::from(self.residual.max_residual_ns)).max(1))
    }

    fn projection_rate(&self) -> Result<i128, ReferenceError> {
        let rate = PPM + i128::from(self.skew_ppm);
        if rate <= 0 {
            return Err(ReferenceError::ArithmeticOverflow);
        }
        Ok(rate)
    }

    fn check_projection_time(&self, time: TimestampNs) -> Result<(), ReferenceError> {
        if time.0 < self.validity.earliest.0 || time.0 > self.validity.latest.0 {
            return Err(ReferenceError::StaleEstimatePastValidity {
                requested: time,
                valid_until: self.validity.latest,
            });
        }
        Ok(())
    }
}

#![forbid(unsafe_code)]
//! Deterministic clock offset and skew estimator interface (FSS-088).
//!
//! Provides typed linear clock synchronization estimation between a reference clock authority
//! and target sensor clocks. Fits offset, skew (ppm), and covariance/residuals over monotonic
//! sample evidence, enforcing explicit failure states for:
//! - Insufficient samples (< minimum required)
//! - Non-monotonic samples (backward or zero progression)
//! - Outlier-dominated fits (residuals exceeding declared tolerance)
//! - Stale estimates requested past validity horizons
//! - Contradicted estimates when new samples diverge beyond tolerance, triggering invalidation
//!   and rollback.

use fss_core::{CaptureInterval, ContentDigest, TimestampNs};

use crate::ReferenceError;

/// A single clock synchronization observation sample.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimeSyncSample {
    /// Monotone 1-based sample sequence.
    pub sequence: u64,
    /// Reference clock timestamp (e.g. from VirtualClock now()).
    pub reference_time: TimestampNs,
    /// Target sensor clock timestamp.
    pub sensor_time: TimestampNs,
    /// Measurement uncertainty bound in nanoseconds.
    pub uncertainty_ns: u64,
    /// Content digest of the sample evidence.
    pub digest: ContentDigest,
}

impl TimeSyncSample {
    /// Constructs a verified synchronization observation sample.
    pub fn new(
        sequence: u64,
        reference_time: TimestampNs,
        sensor_time: TimestampNs,
        uncertainty_ns: u64,
    ) -> Result<Self, ReferenceError> {
        let mut bytes = Vec::with_capacity(8 + 16 + 16 + 8);
        bytes.extend_from_slice(&sequence.to_be_bytes());
        bytes.extend_from_slice(&reference_time.0.to_be_bytes());
        bytes.extend_from_slice(&sensor_time.0.to_be_bytes());
        bytes.extend_from_slice(&uncertainty_ns.to_be_bytes());
        let digest = ContentDigest::sha256(&bytes);
        Ok(Self {
            sequence,
            reference_time,
            sensor_time,
            uncertainty_ns,
            digest,
        })
    }

    /// Computes the raw measured offset: `sensor_time - reference_time`.
    pub fn raw_offset_ns(&self) -> Result<i64, ReferenceError> {
        let diff = self
            .sensor_time
            .0
            .checked_sub(self.reference_time.0)
            .ok_or(ReferenceError::ArithmeticOverflow)?;
        i64::try_from(diff).map_err(|_| ReferenceError::ArithmeticOverflow)
    }
}

/// Goodness-of-fit and covariance metrics for the fitted linear model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncFitResidual {
    /// Maximum absolute residual across all fitted samples in nanoseconds.
    pub max_residual_ns: u64,
    /// Mean squared error across fitted samples in ns^2.
    ///
    /// Saturates at `u64::MAX` (read as "at least `u64::MAX`") when the exact value does not fit;
    /// see `FitVariance` in this module for the conservative saturation policy.
    pub mean_squared_error_ns2: u64,
    /// Estimated variance of the offset parameter in ns^2.
    ///
    /// Computed exactly with a 256-bit intermediate and saturated at `u64::MAX` (maximum
    /// variance) only when the exact floor-rounded value does not fit.
    pub offset_variance_ns2: u64,
    /// Estimated variance of the skew parameter in ppm^2.
    ///
    /// Computed exactly with a 256-bit intermediate and saturated at `u64::MAX` (maximum
    /// variance) only when the exact floor-rounded value does not fit.
    pub skew_variance_ppm2: u64,
    /// Sample count used in the fit.
    pub sample_count: usize,
}

/// A certified, typed clock synchronization estimate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClockSyncEstimate {
    /// Reference time anchor t0 around which the linear model is centered.
    pub reference_anchor: TimestampNs,
    /// Estimated offset at reference_anchor in nanoseconds: `t_sensor(t0) - t0`.
    pub offset_ns: i64,
    /// Estimated clock drift rate in parts-per-million (ppm).
    pub skew_ppm: i64,
    /// Covariance and residual metrics of the fit.
    pub residual: SyncFitResidual,
    /// Time interval over which this estimate is certified valid.
    pub validity: CaptureInterval,
    /// Retained sample evidence used to compute the fit.
    pub sample_evidence: Vec<TimeSyncSample>,
    /// Content-addressed root digest over all sample evidence.
    pub evidence_root: ContentDigest,
    /// Monotone generation number of this estimate.
    pub generation: u64,
}

impl ClockSyncEstimate {
    /// Predicts the sensor capture interval for a given reference timestamp.
    ///
    /// Evaluates validity and expands the interval conservatively with fit residuals.
    pub fn predict_sensor_interval(
        &self,
        ref_time: TimestampNs,
    ) -> Result<CaptureInterval, ReferenceError> {
        if self.sample_evidence.is_empty() {
            return Err(ReferenceError::InsufficientSyncSamples {
                count: 0,
                minimum_required: 1,
            });
        }
        if ref_time.0 < self.validity.earliest.0 || ref_time.0 > self.validity.latest.0 {
            return Err(ReferenceError::StaleEstimatePastValidity {
                requested: ref_time,
                valid_until: self.validity.latest,
            });
        }

        let delta_t = ref_time
            .0
            .checked_sub(self.reference_anchor.0)
            .ok_or(ReferenceError::ArithmeticOverflow)?;

        let skew_offset = delta_t
            .checked_mul(i128::from(self.skew_ppm))
            .ok_or(ReferenceError::ArithmeticOverflow)?
            / 1_000_000;

        let nominal_sensor_time = ref_time
            .0
            .checked_add(i128::from(self.offset_ns))
            .ok_or(ReferenceError::ArithmeticOverflow)?
            .checked_add(skew_offset)
            .ok_or(ReferenceError::ArithmeticOverflow)?;

        // Conservative uncertainty: maximum sample uncertainty + fit max residual (with minimum 1 ns floor)
        let max_sample_uncert = self
            .sample_evidence
            .iter()
            .map(|s| s.uncertainty_ns)
            .max()
            .unwrap_or(0);
        let total_uncertainty = max_sample_uncert
            .saturating_add(self.residual.max_residual_ns)
            .max(1);

        let earliest = nominal_sensor_time
            .checked_sub(i128::from(total_uncertainty))
            .ok_or(ReferenceError::ArithmeticOverflow)?;
        let latest = nominal_sensor_time
            .checked_add(i128::from(total_uncertainty))
            .ok_or(ReferenceError::ArithmeticOverflow)?;

        CaptureInterval::new(TimestampNs(earliest), TimestampNs(latest))
            .map_err(ReferenceError::Contract)
    }

    /// Predicts the reference capture interval for a given sensor timestamp.
    pub fn predict_reference_interval(
        &self,
        sensor_time: TimestampNs,
    ) -> Result<CaptureInterval, ReferenceError> {
        if self.sample_evidence.is_empty() {
            return Err(ReferenceError::InsufficientSyncSamples {
                count: 0,
                minimum_required: 1,
            });
        }
        // Approximate inverted time: ref ~= (sensor - offset) / (1 + skew/1e6)
        // Since |skew| <= 500_000 ppm, 1 + skew_ppm/1e6 = (1_000_000 + skew_ppm) / 1_000_000
        let effective_rate = 1_000_000_i128
            .checked_add(i128::from(self.skew_ppm))
            .ok_or(ReferenceError::ArithmeticOverflow)?;
        if effective_rate <= 0 {
            return Err(ReferenceError::ArithmeticOverflow);
        }

        let delta_sensor = sensor_time
            .0
            .checked_sub(self.reference_anchor.0)
            .ok_or(ReferenceError::ArithmeticOverflow)?
            .checked_sub(i128::from(self.offset_ns))
            .ok_or(ReferenceError::ArithmeticOverflow)?;

        let delta_ref = delta_sensor
            .checked_mul(1_000_000)
            .ok_or(ReferenceError::ArithmeticOverflow)?
            / effective_rate;

        let nominal_ref_time = self
            .reference_anchor
            .0
            .checked_add(delta_ref)
            .ok_or(ReferenceError::ArithmeticOverflow)?;

        let ref_ts = TimestampNs(nominal_ref_time);
        if ref_ts.0 < self.validity.earliest.0 || ref_ts.0 > self.validity.latest.0 {
            return Err(ReferenceError::StaleEstimatePastValidity {
                requested: ref_ts,
                valid_until: self.validity.latest,
            });
        }

        let max_sample_uncert = self
            .sample_evidence
            .iter()
            .map(|s| s.uncertainty_ns)
            .max()
            .unwrap_or(0);
        let total_uncertainty = max_sample_uncert
            .saturating_add(self.residual.max_residual_ns)
            .max(1);

        let earliest = nominal_ref_time
            .checked_sub(i128::from(total_uncertainty))
            .ok_or(ReferenceError::ArithmeticOverflow)?;
        let latest = nominal_ref_time
            .checked_add(i128::from(total_uncertainty))
            .ok_or(ReferenceError::ArithmeticOverflow)?;

        CaptureInterval::new(TimestampNs(earliest), TimestampNs(latest))
            .map_err(ReferenceError::Contract)
    }

    /// Verifies whether a new synchronization sample is consistent with this estimate.
    ///
    /// Rejects with [`ReferenceError::ContradictedEstimate`] if the sample's measured offset
    /// deviates from the model prediction by more than `max_deviation_ns`.
    pub fn validate_sample(
        &self,
        sample: &TimeSyncSample,
        max_deviation_ns: u64,
    ) -> Result<(), ReferenceError> {
        let delta_t = sample
            .reference_time
            .0
            .checked_sub(self.reference_anchor.0)
            .ok_or(ReferenceError::ArithmeticOverflow)?;

        let skew_offset = delta_t
            .checked_mul(i128::from(self.skew_ppm))
            .ok_or(ReferenceError::ArithmeticOverflow)?
            / 1_000_000;

        let expected_offset_raw = i128::from(self.offset_ns)
            .checked_add(skew_offset)
            .ok_or(ReferenceError::ArithmeticOverflow)?;
        let expected_offset_ns =
            i64::try_from(expected_offset_raw).map_err(|_| ReferenceError::ArithmeticOverflow)?;

        let observed_offset_ns = sample.raw_offset_ns()?;

        let deviation =
            (i128::from(observed_offset_ns) - i128::from(expected_offset_ns)).unsigned_abs();
        if deviation > u128::from(max_deviation_ns) {
            let deviation_ns = u64::try_from(deviation).unwrap_or(u64::MAX);
            return Err(ReferenceError::ContradictedEstimate {
                expected_offset_ns,
                observed_offset_ns,
                deviation_ns,
            });
        }

        Ok(())
    }
}

/// Smallest `min_samples` that determines a two-parameter (offset, skew) linear fit.
const MIN_FIT_SAMPLES: usize = 2;

/// Upper bound of `max_outlier_basis_points` (10_000 basis points = 100%).
const MAX_OUTLIER_BASIS_POINTS: u16 = 10_000;

/// Scale from a squared dimensionless slope to ppm^2 (`(10^6)^2`).
const PPM2_PER_UNIT_SLOPE2: u128 = 1_000_000_000_000;

/// Configuration parameters for the clock offset and skew estimator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EstimatorConfig {
    /// Minimum samples required to compute a fit (minimum 2).
    pub min_samples: usize,
    /// Maximum residual allowed for a nominal sample before being classified as an outlier.
    pub max_residual_tolerance_ns: u64,
    /// Maximum fraction of outliers allowed (in basis points, 0..=10_000, e.g. 2_000 = 20%).
    pub max_outlier_basis_points: u16,
    /// Validity horizon beyond the last sample in nanoseconds.
    pub validity_horizon_ns: u64,
    /// Contradiction tolerance in nanoseconds for new samples.
    pub contradiction_tolerance_ns: u64,
}

impl EstimatorConfig {
    /// Validates the documented configuration bounds.
    ///
    /// # Errors
    ///
    /// Returns [`ReferenceError::InvalidEstimatorConfig`] when `min_samples < 2` (an offset and
    /// skew fit is undetermined with fewer samples, and an empty sample set has no reference
    /// anchor) or when `max_outlier_basis_points > 10_000` (more than 100% outliers).
    pub fn validate(&self) -> Result<(), ReferenceError> {
        if self.min_samples < MIN_FIT_SAMPLES {
            return Err(ReferenceError::InvalidEstimatorConfig {
                parameter: "min_samples",
                value: u64::try_from(self.min_samples)
                    .map_err(|_| ReferenceError::ArithmeticOverflow)?,
                requirement: "must be at least 2",
            });
        }
        if self.max_outlier_basis_points > MAX_OUTLIER_BASIS_POINTS {
            return Err(ReferenceError::InvalidEstimatorConfig {
                parameter: "max_outlier_basis_points",
                value: u64::from(self.max_outlier_basis_points),
                requirement: "must be at most 10000",
            });
        }
        Ok(())
    }
}

impl Default for EstimatorConfig {
    fn default() -> Self {
        Self {
            min_samples: 3,
            max_residual_tolerance_ns: 5_000_000,   // 5 ms
            max_outlier_basis_points: 2_500,        // 25%
            validity_horizon_ns: 60_000_000_000,    // 60 seconds
            contradiction_tolerance_ns: 10_000_000, // 10 ms
        }
    }
}

/// Lifecycle state of the estimator state machine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EstimatorState {
    /// Estimator has not yet received sufficient samples to fit.
    Uncalibrated,
    /// An active, certified clock estimate is in effect.
    Synchronized(ClockSyncEstimate),
    /// A previous estimate was contradicted by new samples and has been invalidated.
    Invalidated {
        /// The invalidated estimate.
        prior_estimate: ClockSyncEstimate,
        /// The sample that caused the contradiction.
        contradicting_sample: TimeSyncSample,
        /// Reason description.
        reason: String,
    },
}

/// Deterministic, stateful clock offset and skew estimator.
#[derive(Clone, Debug)]
pub struct ClockOffsetSkewEstimator {
    config: EstimatorConfig,
    samples: Vec<TimeSyncSample>,
    active_estimate: Option<ClockSyncEstimate>,
    prior_estimates: Vec<ClockSyncEstimate>,
    state: EstimatorState,
    generation_counter: u64,
}

impl ClockOffsetSkewEstimator {
    /// Creates a new estimator after validating the configuration.
    ///
    /// # Errors
    ///
    /// Returns [`ReferenceError::InvalidEstimatorConfig`] when `config` violates a bound checked
    /// by [`EstimatorConfig::validate`].
    pub fn new(config: EstimatorConfig) -> Result<Self, ReferenceError> {
        config.validate()?;
        Ok(Self {
            config,
            samples: Vec::new(),
            active_estimate: None,
            prior_estimates: Vec::new(),
            state: EstimatorState::Uncalibrated,
            generation_counter: 0,
        })
    }

    /// Returns the active estimator state.
    #[must_use]
    pub const fn state(&self) -> &EstimatorState {
        &self.state
    }

    /// Returns a reference to the active estimate if synchronized.
    #[must_use]
    pub const fn active_estimate(&self) -> Option<&ClockSyncEstimate> {
        self.active_estimate.as_ref()
    }

    /// Returns the collection of all collected samples.
    #[must_use]
    pub fn samples(&self) -> &[TimeSyncSample] {
        &self.samples
    }

    /// Appends a new synchronization sample into the estimator.
    ///
    /// Strictly verifies monotonicity:
    /// - `reference_time` must be strictly greater than the previous sample's `reference_time`.
    /// - `sensor_time` must be strictly greater than the previous sample's `sensor_time`.
    /// - `sequence` must be strictly greater than the previous sample's `sequence`.
    ///
    /// If an active estimate is present, tests for contradictions:
    /// - If contradicted, automatically transitions to [`EstimatorState::Invalidated`] and
    ///   returns [`ReferenceError::ContradictedEstimate`].
    pub fn add_sample(&mut self, sample: TimeSyncSample) -> Result<(), ReferenceError> {
        if let Some(prev) = self.samples.last() {
            if sample.reference_time.0 <= prev.reference_time.0 {
                return Err(ReferenceError::NonMonotonicSyncSamples {
                    previous: prev.reference_time,
                    current: sample.reference_time,
                });
            }
            if sample.sensor_time.0 <= prev.sensor_time.0 {
                return Err(ReferenceError::NonMonotonicSyncSamples {
                    previous: prev.sensor_time,
                    current: sample.sensor_time,
                });
            }
            if sample.sequence <= prev.sequence {
                return Err(ReferenceError::NonMonotonicSyncSequence {
                    previous: prev.sequence,
                    current: sample.sequence,
                });
            }
        }

        // Check contradiction against current active or prior estimate
        let candidate_estimate = match &self.state {
            EstimatorState::Synchronized(est) => Some(est),
            EstimatorState::Invalidated { prior_estimate, .. } => Some(prior_estimate),
            EstimatorState::Uncalibrated => None,
        };
        if let Some(estimate) = candidate_estimate
            && let Err(err) =
                estimate.validate_sample(&sample, self.config.contradiction_tolerance_ns)
        {
            if self.active_estimate.is_some() {
                let prior = estimate.clone();
                let reason = format!("{err}");
                self.state = EstimatorState::Invalidated {
                    prior_estimate: prior,
                    contradicting_sample: sample.clone(),
                    reason,
                };
                self.active_estimate = None;
            }
            return Err(err);
        }

        self.samples.push(sample);
        Ok(())
    }

    fn fit_ols(
        samples: &[TimeSyncSample],
        reference_anchor: TimestampNs,
    ) -> Result<(i64, i64, i128, i128), ReferenceError> {
        let n = samples.len();
        let n_i128 = i128::try_from(n).map_err(|_| ReferenceError::ArithmeticOverflow)?;
        let mut sum_x: i128 = 0;
        let mut sum_y: i128 = 0;
        let mut sum_xx: i128 = 0;
        let mut sum_xy: i128 = 0;

        for sample in samples {
            let x = sample
                .reference_time
                .0
                .checked_sub(reference_anchor.0)
                .ok_or(ReferenceError::ArithmeticOverflow)?;
            let y = sample
                .sensor_time
                .0
                .checked_sub(sample.reference_time.0)
                .ok_or(ReferenceError::ArithmeticOverflow)?;

            sum_x = sum_x
                .checked_add(x)
                .ok_or(ReferenceError::ArithmeticOverflow)?;
            sum_y = sum_y
                .checked_add(y)
                .ok_or(ReferenceError::ArithmeticOverflow)?;
            sum_xx = sum_xx
                .checked_add(x.checked_mul(x).ok_or(ReferenceError::ArithmeticOverflow)?)
                .ok_or(ReferenceError::ArithmeticOverflow)?;
            sum_xy = sum_xy
                .checked_add(x.checked_mul(y).ok_or(ReferenceError::ArithmeticOverflow)?)
                .ok_or(ReferenceError::ArithmeticOverflow)?;
        }

        let denominator = n_i128
            .checked_mul(sum_xx)
            .ok_or(ReferenceError::ArithmeticOverflow)?
            .checked_sub(
                sum_x
                    .checked_mul(sum_x)
                    .ok_or(ReferenceError::ArithmeticOverflow)?,
            )
            .ok_or(ReferenceError::ArithmeticOverflow)?;

        if denominator <= 0 {
            return Err(ReferenceError::ArithmeticOverflow);
        }

        let numerator_skew = n_i128
            .checked_mul(sum_xy)
            .ok_or(ReferenceError::ArithmeticOverflow)?
            .checked_sub(
                sum_x
                    .checked_mul(sum_y)
                    .ok_or(ReferenceError::ArithmeticOverflow)?,
            )
            .ok_or(ReferenceError::ArithmeticOverflow)?;

        let skew_ppm_raw = numerator_skew
            .checked_mul(1_000_000)
            .ok_or(ReferenceError::ArithmeticOverflow)?
            / denominator;
        let skew_ppm =
            i64::try_from(skew_ppm_raw).map_err(|_| ReferenceError::ArithmeticOverflow)?;

        let numerator_offset = sum_y
            .checked_mul(sum_xx)
            .ok_or(ReferenceError::ArithmeticOverflow)?
            .checked_sub(
                sum_x
                    .checked_mul(sum_xy)
                    .ok_or(ReferenceError::ArithmeticOverflow)?,
            )
            .ok_or(ReferenceError::ArithmeticOverflow)?;

        let offset_ns_raw = numerator_offset / denominator;
        let offset_ns =
            i64::try_from(offset_ns_raw).map_err(|_| ReferenceError::ArithmeticOverflow)?;

        Ok((offset_ns, skew_ppm, sum_xx, denominator))
    }

    /// Fits a deterministic linear model from the accumulated samples.
    ///
    /// Emits typed errors on failure:
    /// - [`ReferenceError::InsufficientSyncSamples`] if fewer than `min_samples` exist.
    /// - [`ReferenceError::OutlierDominatedFit`] if outlier ratio exceeds threshold.
    pub fn fit(&mut self) -> Result<ClockSyncEstimate, ReferenceError> {
        let n = self.samples.len();
        if n < self.config.min_samples {
            return Err(ReferenceError::InsufficientSyncSamples {
                count: n,
                minimum_required: self.config.min_samples,
            });
        }

        let (Some(first), Some(last)) = (self.samples.first(), self.samples.last()) else {
            return Err(ReferenceError::InsufficientSyncSamples {
                count: n,
                minimum_required: self.config.min_samples,
            });
        };
        let reference_anchor = first.reference_time;

        let mut active_samples: Vec<TimeSyncSample> = self.samples.clone();
        let mut outlier_count: usize = 0;
        let mut worst_residual_ns: u64 = 0;

        let (offset_ns, skew_ppm, sum_xx, denominator) = loop {
            let (cur_offset, cur_skew, cur_sxx, cur_den) =
                Self::fit_ols(&active_samples, reference_anchor)?;

            let mut max_res: u64 = 0;
            let mut peel_idx: usize = 0;

            for (idx, sample) in active_samples.iter().enumerate() {
                let x = sample.reference_time.0 - reference_anchor.0;
                let y = sample.sensor_time.0 - sample.reference_time.0;

                let predicted_y = i128::from(cur_offset) + (i128::from(cur_skew) * x / 1_000_000);
                let residual = (y - predicted_y).unsigned_abs();
                let residual_u64 = u64::try_from(residual).unwrap_or(u64::MAX);

                if residual_u64 > max_res {
                    max_res = residual_u64;
                    peel_idx = idx;
                }
            }

            if max_res > worst_residual_ns {
                worst_residual_ns = max_res;
            }

            if max_res <= self.config.max_residual_tolerance_ns {
                break (cur_offset, cur_skew, cur_sxx, cur_den);
            }

            outlier_count += 1;
            let outlier_bp = (outlier_count as u64 * 10_000) / n as u64;
            if outlier_bp > u64::from(self.config.max_outlier_basis_points) {
                return Err(ReferenceError::OutlierDominatedFit {
                    outlier_count,
                    total_samples: n,
                    max_residual_ns: worst_residual_ns,
                });
            }

            active_samples.remove(peel_idx);

            if active_samples.len() < self.config.min_samples {
                return Err(ReferenceError::InsufficientSyncSamples {
                    count: active_samples.len(),
                    minimum_required: self.config.min_samples,
                });
            }
        };

        let eff_n = active_samples.len();
        let mut max_residual_ns: u64 = 0;
        // `None` records that the exact sum of squared residuals exceeded `u128::MAX`.
        let mut sum_sq_residuals: Option<u128> = Some(0);

        for sample in &active_samples {
            let x = sample.reference_time.0 - reference_anchor.0;
            let y = sample.sensor_time.0 - sample.reference_time.0;

            let predicted_y = i128::from(offset_ns) + (i128::from(skew_ppm) * x / 1_000_000);
            let residual = (y - predicted_y).unsigned_abs();
            let residual_u64 = u64::try_from(residual).unwrap_or(u64::MAX);

            if residual_u64 > max_residual_ns {
                max_residual_ns = residual_u64;
            }
            sum_sq_residuals = sum_sq_residuals.and_then(|acc| {
                residual
                    .checked_mul(residual)
                    .and_then(|square| acc.checked_add(square))
            });
        }

        let variance = FitVariance::from_residuals(sum_sq_residuals, eff_n, sum_xx, denominator)?;
        let residual = SyncFitResidual {
            max_residual_ns,
            mean_squared_error_ns2: variance.mean_squared_error_ns2,
            offset_variance_ns2: variance.offset_variance_ns2,
            skew_variance_ppm2: variance.skew_variance_ppm2,
            sample_count: eff_n,
        };

        // Validity interval: [first_sample.reference_time, last_sample.reference_time + validity_horizon_ns]
        let valid_latest_raw = last
            .reference_time
            .0
            .checked_add(i128::from(self.config.validity_horizon_ns))
            .ok_or(ReferenceError::ArithmeticOverflow)?;
        let validity = CaptureInterval::new(first.reference_time, TimestampNs(valid_latest_raw))
            .map_err(ReferenceError::Contract)?;

        // Canonical evidence root computed over effective inlier samples
        let mut evidence_bytes = Vec::with_capacity(32 + 8 + eff_n * 32);
        evidence_bytes.extend_from_slice(b"fss.clock_sync_evidence.v1");
        evidence_bytes.extend_from_slice(&(eff_n as u64).to_be_bytes());
        for s in &active_samples {
            evidence_bytes.extend_from_slice(&s.digest.bytes());
        }
        let evidence_root = ContentDigest::sha256(&evidence_bytes);

        self.generation_counter = self
            .generation_counter
            .checked_add(1)
            .ok_or(ReferenceError::ArithmeticOverflow)?;

        let estimate = ClockSyncEstimate {
            reference_anchor,
            offset_ns,
            skew_ppm,
            residual,
            validity,
            sample_evidence: active_samples,
            evidence_root,
            generation: self.generation_counter,
        };

        if let Some(prev_active) = self.active_estimate.take() {
            self.prior_estimates.push(prev_active);
        }

        self.active_estimate = Some(estimate.clone());
        self.state = EstimatorState::Synchronized(estimate.clone());
        Ok(estimate)
    }

    /// Rollback the current estimate, restoring the immediately prior valid estimate.
    ///
    /// If a prior estimate exists, its validity horizon is clamped to before the contradicting event,
    /// and it becomes active again.
    /// If no prior estimate exists, transitions to [`EstimatorState::Uncalibrated`].
    pub fn rollback(&mut self) -> Result<Option<ClockSyncEstimate>, ReferenceError> {
        let candidate = match &self.state {
            EstimatorState::Invalidated {
                prior_estimate,
                contradicting_sample,
                ..
            } => {
                let mut prior = prior_estimate.clone();
                let clamped_latest = TimestampNs(
                    contradicting_sample
                        .reference_time
                        .0
                        .saturating_sub(1)
                        .max(prior.validity.earliest.0),
                );
                prior.validity = CaptureInterval::new(prior.validity.earliest, clamped_latest)
                    .map_err(ReferenceError::Contract)?;
                Some(prior)
            }
            _ => self.prior_estimates.pop(),
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

    /// Explicitly invalidates the active estimate.
    pub fn invalidate(&mut self, sample: TimeSyncSample, reason: impl Into<String>) {
        if let Some(active) = self.active_estimate.take() {
            self.state = EstimatorState::Invalidated {
                prior_estimate: active,
                contradicting_sample: sample,
                reason: reason.into(),
            };
        }
    }
}

/// Integer fit-quality statistics of the ordinary-least-squares clock model.
///
/// For `n` inlier samples with anchored abscissae `x`, `mse = floor(sum(r^2) / n)`,
/// `denominator = n * sum(x^2) - sum(x)^2`, and
/// - `offset_variance_ns2 = floor(mse * sum(x^2) / denominator)`,
/// - `skew_variance_ppm2 = floor(mse * n * 10^12 / denominator)`.
///
/// # Conservative saturation, not a typed error
///
/// Each value saturates to `u64::MAX` when its exact value does not fit. It never wraps.
/// Saturation was chosen over a typed error because of how the values are consumed. They are
/// reported fit-quality metrics in [`SyncFitResidual`]. They do not feed the predicted capture
/// intervals, which widen by `max_residual_ns` plus sample uncertainty. They do not feed any
/// accept/reject gate either, because the residual-tolerance and outlier gates have already
/// accepted the fit when they are computed. Returning an error here would discard a valid
/// estimate only because a reporting metric is unrepresentable. `u64::MAX` is the
/// maximum-variance (least confident) reading, so a saturated value never understates
/// uncertainty.
///
/// Products are formed with a 256-bit intermediate ([`mul_div_floor_saturating_u64`]), so
/// saturation happens only when the exact floor-rounded result exceeds `u64::MAX`. A realistic
/// day-long fit whose `mse * sum(x^2)` exceeds `u128::MAX` still reports its exact variance. If
/// the sum of squared residuals itself exceeds `u128::MAX`, the true mean square is unknown and
/// all three metrics take the maximum.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FitVariance {
    mean_squared_error_ns2: u64,
    offset_variance_ns2: u64,
    skew_variance_ppm2: u64,
}

impl FitVariance {
    /// Every metric at the conservative maximum-variance value.
    const SATURATED: Self = Self {
        mean_squared_error_ns2: u64::MAX,
        offset_variance_ns2: u64::MAX,
        skew_variance_ppm2: u64::MAX,
    };

    /// Derives the metrics from the exact sum of squared residuals.
    ///
    /// `sum_sq_residuals` is `None` when that sum exceeded `u128::MAX`.
    fn from_residuals(
        sum_sq_residuals: Option<u128>,
        sample_count: usize,
        sum_xx: i128,
        denominator: i128,
    ) -> Result<Self, ReferenceError> {
        if denominator <= 0 {
            return Err(ReferenceError::ArithmeticOverflow);
        }
        if sample_count == 0 {
            return Err(ReferenceError::InsufficientSyncSamples {
                count: 0,
                minimum_required: MIN_FIT_SAMPLES,
            });
        }
        let Some(sum_sq) = sum_sq_residuals else {
            return Ok(Self::SATURATED);
        };

        let n = u128::try_from(sample_count).map_err(|_| ReferenceError::ArithmeticOverflow)?;
        let mse = sum_sq / n;
        let divisor = denominator.unsigned_abs();
        let offset_variance_ns2 = mul_div_floor_saturating_u64(mse, sum_xx.unsigned_abs(), divisor)
            .ok_or(ReferenceError::ArithmeticOverflow)?;
        let skew_scale = n
            .checked_mul(PPM2_PER_UNIT_SLOPE2)
            .ok_or(ReferenceError::ArithmeticOverflow)?;
        let skew_variance_ppm2 = mul_div_floor_saturating_u64(mse, skew_scale, divisor)
            .ok_or(ReferenceError::ArithmeticOverflow)?;

        Ok(Self {
            // Conservative saturation: `u64::MAX` means "at least u64::MAX" (see type docs).
            mean_squared_error_ns2: u64::try_from(mse).unwrap_or(u64::MAX),
            offset_variance_ns2,
            skew_variance_ppm2,
        })
    }
}

/// Mask selecting the low 64 bits of a `u128`.
const LOW_64_MASK: u128 = 0xFFFF_FFFF_FFFF_FFFF;

/// Full 256-bit product of two `u128` values as `(high, low)` 128-bit halves.
const fn widening_mul_u128(a: u128, b: u128) -> (u128, u128) {
    let (a_high, a_low) = (a >> 64, a & LOW_64_MASK);
    let (b_high, b_low) = (b >> 64, b & LOW_64_MASK);
    // Each partial product of two 64-bit limbs is below 2^128.
    let low_low = a_low * b_low;
    let low_high = a_low * b_high;
    let high_low = a_high * b_low;
    let high_high = a_high * b_high;
    // Three terms below 2^64 each: the sum stays below 3 * 2^64.
    let middle = (low_low >> 64) + (low_high & LOW_64_MASK) + (high_low & LOW_64_MASK);
    let low = (low_low & LOW_64_MASK) | (middle << 64);
    // The exact product is below 2^256, so its high half cannot overflow.
    let high = high_high + (low_high >> 64) + (high_low >> 64) + (middle >> 64);
    (high, low)
}

/// Computes `floor(a * b / divisor)` exactly and narrows it to `u64`, saturating to `u64::MAX`
/// (conservative maximum) when the exact quotient does not fit.
///
/// The product is formed with checked `u128` arithmetic when it fits and with a 256-bit
/// intermediate otherwise, so no intermediate ever overflows or wraps. Returns `None` only when
/// `divisor` is zero.
fn mul_div_floor_saturating_u64(a: u128, b: u128, divisor: u128) -> Option<u64> {
    if divisor == 0 {
        return None;
    }
    if let Some(product) = a.checked_mul(b) {
        return Some(u64::try_from(product / divisor).unwrap_or(u64::MAX));
    }
    let (high, low) = widening_mul_u128(a, b);
    if high >= divisor {
        // Quotient is at least 2^128.
        return Some(u64::MAX);
    }
    // Restoring long division of the 256-bit dividend: `remainder < divisor` is invariant.
    let mut remainder = high;
    let mut quotient: u64 = 0;
    for bit in (0..128_u32).rev() {
        let carry = remainder >> 127;
        remainder = (remainder << 1) | ((low >> bit) & 1);
        // With `carry` set the true shifted remainder is `2^128 + remainder`, which exceeds
        // `divisor`; the difference is below `divisor`, so the wrapping subtraction is exact.
        if carry == 1 || remainder >= divisor {
            remainder = remainder.wrapping_sub(divisor);
            if bit >= 64 {
                return Some(u64::MAX);
            }
            quotient |= 1_u64 << bit;
        }
    }
    Some(quotient)
}

#[cfg(test)]
mod tests {
    use super::{FitVariance, mul_div_floor_saturating_u64};
    use crate::ReferenceError;

    #[test]
    fn mul_div_matches_direct_quotient_when_product_fits() -> Result<(), String> {
        let max64 = u128::from(u64::MAX);
        let cases: [(u128, u128, u128); 5] = [
            (0, 5, 3),
            (7, 9, 4),
            (10_000_000_000, 1_000_000, 3),
            (max64, max64, max64),
            (max64, max64, 1_u128 << 64),
        ];
        for (a, b, divisor) in cases {
            let direct = a.checked_mul(b).ok_or("product overflowed")? / divisor;
            let expected = u64::try_from(direct).map_err(|error| error.to_string())?;
            assert_eq!(mul_div_floor_saturating_u64(a, b, divisor), Some(expected));
        }
        Ok(())
    }

    #[test]
    fn mul_div_is_exact_when_product_exceeds_u128() -> Result<(), String> {
        // Realistic day-long fit: mse = 1e10 ns^2, sum_xx = s^2 * 328_350 and
        // denominator = s^2 * 8_332_500 with s = 864 s; mse * sum_xx ~ 2.45e39 > u128::MAX.
        let step_sq = 864_000_000_000_u128 * 864_000_000_000;
        let mse = 10_000_000_000_u128;
        let sum_xx = step_sq * 328_350;
        let denominator = step_sq * 8_332_500;
        assert!(mse.checked_mul(sum_xx).is_none());
        let expected =
            u64::try_from(mse * 328_350 / 8_332_500).map_err(|error| error.to_string())?;
        assert_eq!(
            mul_div_floor_saturating_u64(mse, sum_xx, denominator),
            Some(expected)
        );

        // Divisor above 2^127 exercises the carry branch of the long division.
        let big = u128::MAX - 7;
        let factor = 0xDEAD_BEEF_1234_5678_u128;
        assert!(big.checked_mul(factor).is_none());
        assert_eq!(
            mul_div_floor_saturating_u64(big, factor, big),
            Some(0xDEAD_BEEF_1234_5678)
        );

        let half = 1_u128 << 127;
        assert_eq!(
            mul_div_floor_saturating_u64(half, (1_u128 << 63) + 7, half),
            Some((1_u64 << 63) + 7)
        );
        assert_eq!(
            mul_div_floor_saturating_u64(u128::MAX, (1_u128 << 64) - 2, u128::MAX),
            Some(u64::MAX - 1)
        );
        Ok(())
    }

    #[test]
    fn mul_div_saturates_only_when_exact_quotient_exceeds_u64() {
        // Exact quotient 2^64: one past u64::MAX.
        assert_eq!(
            mul_div_floor_saturating_u64(u128::MAX, 1_u128 << 64, u128::MAX),
            Some(u64::MAX)
        );
        // Exact quotient 2^73 via the long-division path.
        assert_eq!(
            mul_div_floor_saturating_u64(1_u128 << 100, 1_u128 << 100, 1_u128 << 127),
            Some(u64::MAX)
        );
        // Exact quotient u128::MAX: the high half alone decides.
        assert_eq!(
            mul_div_floor_saturating_u64(u128::MAX, u128::MAX, u128::MAX),
            Some(u64::MAX)
        );
        // Exact quotient 2^63 fits.
        assert_eq!(
            mul_div_floor_saturating_u64(1_u128 << 100, 1_u128 << 90, 1_u128 << 127),
            Some(1_u64 << 63)
        );
        assert_eq!(mul_div_floor_saturating_u64(1, 1, 0), None);
    }

    #[test]
    fn fit_variance_saturates_all_metrics_when_sum_of_squares_overflows() -> Result<(), String> {
        let variance = FitVariance::from_residuals(None, 3, 2_000, 2_400)
            .map_err(|error| error.to_string())?;
        assert_eq!(variance, FitVariance::SATURATED);
        assert_eq!(variance.mean_squared_error_ns2, u64::MAX);
        assert_eq!(variance.offset_variance_ns2, u64::MAX);
        assert_eq!(variance.skew_variance_ppm2, u64::MAX);
        Ok(())
    }

    #[test]
    fn fit_variance_rejects_degenerate_inputs_with_typed_errors() {
        assert!(matches!(
            FitVariance::from_residuals(Some(9), 3, 2_000, 0),
            Err(ReferenceError::ArithmeticOverflow)
        ));
        assert!(matches!(
            FitVariance::from_residuals(Some(9), 3, 2_000, -1),
            Err(ReferenceError::ArithmeticOverflow)
        ));
        assert!(matches!(
            FitVariance::from_residuals(Some(9), 0, 2_000, 2_400),
            Err(ReferenceError::InsufficientSyncSamples {
                count: 0,
                minimum_required: 2
            })
        ));
    }
}

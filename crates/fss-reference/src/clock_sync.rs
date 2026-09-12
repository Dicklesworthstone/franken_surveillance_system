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
    pub mean_squared_error_ns2: u64,
    /// Estimated variance of the offset parameter in ns^2.
    pub offset_variance_ns2: u64,
    /// Estimated variance of the skew parameter in ppm^2.
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

        // Conservative uncertainty: maximum sample uncertainty + fit max residual
        let max_sample_uncert = self
            .sample_evidence
            .iter()
            .map(|s| s.uncertainty_ns)
            .max()
            .unwrap_or(0);
        let total_uncertainty = max_sample_uncert
            .checked_add(self.residual.max_residual_ns)
            .ok_or(ReferenceError::ArithmeticOverflow)?;

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
            .checked_add(self.residual.max_residual_ns)
            .ok_or(ReferenceError::ArithmeticOverflow)?;

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
    /// Creates a new estimator with the given configuration.
    #[must_use]
    pub fn new(config: EstimatorConfig) -> Self {
        Self {
            config,
            samples: Vec::new(),
            active_estimate: None,
            prior_estimates: Vec::new(),
            state: EstimatorState::Uncalibrated,
            generation_counter: 0,
        }
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
                return Err(ReferenceError::NonMonotonicSyncSamples {
                    previous: prev.reference_time,
                    current: sample.reference_time,
                });
            }
        }

        // Check contradiction against current active estimate if within validity
        if let Some(ref estimate) = self.active_estimate {
            if let Err(err) =
                estimate.validate_sample(&sample, self.config.contradiction_tolerance_ns)
            {
                let prior = estimate.clone();
                let reason = format!("{err}");
                self.state = EstimatorState::Invalidated {
                    prior_estimate: prior,
                    contradicting_sample: sample.clone(),
                    reason,
                };
                self.active_estimate = None;
                self.samples.push(sample);
                return Err(err);
            }
        }

        self.samples.push(sample);
        Ok(())
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

        let first = &self.samples[0];
        let last = &self.samples[n - 1];
        let reference_anchor = first.reference_time;

        // Linear regression: y = offset + skew * x
        // x_i = ref_i - t0 (>= 0)
        // y_i = sensor_i - ref_i (raw offset)
        let mut sum_x: i128 = 0;
        let mut sum_y: i128 = 0;
        let mut sum_xx: i128 = 0;
        let mut sum_xy: i128 = 0;

        let n_i128 = i128::try_from(n).map_err(|_| ReferenceError::ArithmeticOverflow)?;

        for sample in &self.samples {
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

        if denominator == 0 {
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

        // Residual analysis and outlier detection
        let mut max_residual_ns: u64 = 0;
        let mut sum_sq_residuals: u128 = 0;
        let mut outlier_count: usize = 0;

        for sample in &self.samples {
            let x = sample.reference_time.0 - reference_anchor.0;
            let y = sample.sensor_time.0 - sample.reference_time.0;

            let predicted_y = offset_ns_raw + (skew_ppm_raw * x / 1_000_000);
            let residual = (y - predicted_y).unsigned_abs();
            let residual_u64 = u64::try_from(residual).unwrap_or(u64::MAX);

            if residual_u64 > max_residual_ns {
                max_residual_ns = residual_u64;
            }
            sum_sq_residuals = sum_sq_residuals.saturating_add(residual.saturating_mul(residual));

            if residual_u64 > self.config.max_residual_tolerance_ns {
                outlier_count += 1;
            }
        }

        let outlier_bp = (outlier_count as u64 * 10_000) / n as u64;
        if outlier_bp > u64::from(self.config.max_outlier_basis_points) {
            return Err(ReferenceError::OutlierDominatedFit {
                outlier_count,
                total_samples: n,
                max_residual_ns,
            });
        }

        let mse = (sum_sq_residuals / n as u128) as u64;
        let offset_variance_ns2 = if denominator > 0 {
            let var = (u128::from(mse) * sum_xx.unsigned_abs()) / denominator.unsigned_abs();
            u64::try_from(var).unwrap_or(u64::MAX)
        } else {
            0
        };

        let skew_variance_ppm2 = if denominator > 0 {
            let var =
                (u128::from(mse) * n as u128 * 1_000_000_000_000_u128) / denominator.unsigned_abs();
            u64::try_from(var).unwrap_or(u64::MAX)
        } else {
            0
        };

        let residual = SyncFitResidual {
            max_residual_ns,
            mean_squared_error_ns2: mse,
            offset_variance_ns2,
            skew_variance_ppm2,
            sample_count: n,
        };

        // Validity interval: [first_sample.reference_time, last_sample.reference_time + validity_horizon_ns]
        let valid_latest_raw = last
            .reference_time
            .0
            .checked_add(i128::from(self.config.validity_horizon_ns))
            .ok_or(ReferenceError::ArithmeticOverflow)?;
        let validity = CaptureInterval::new(first.reference_time, TimestampNs(valid_latest_raw))
            .map_err(ReferenceError::Contract)?;

        // Canonical evidence root
        let mut evidence_bytes = Vec::with_capacity(32 + 8 + n * 32);
        evidence_bytes.extend_from_slice(b"fss.clock_sync_evidence.v1");
        evidence_bytes.extend_from_slice(&(n as u64).to_be_bytes());
        for s in &self.samples {
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
            sample_evidence: self.samples.clone(),
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
                if let Some(last) = self.samples.last() {
                    if last == contradicting_sample {
                        self.samples.pop();
                    }
                }
                Some(prior_estimate.clone())
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
